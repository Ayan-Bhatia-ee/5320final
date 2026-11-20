// ESE5320 Project - encoder host code, SHA-256 on the FPGA (FPGA milestone, baseline)
//
// Flow:  Ethernet packets -> CDC (ARM) -> SHA-256 (FPGA kernel, OpenCL) -> dedup (ARM)
//                                                 -+-> duplicate header
//                                                  +-> LZW (ARM) -> output buffer -> file
//
// Baseline version: one kernel call per chunk (copy in, run, copy out, wait).
// Batching (step 4): one kernel call hashes up to SHA_BATCH_MAX_CHUNKS chunks (layout in sha_kernel.h), which
// spreads the OpenCL call overhead (~200 us per call) over the whole batch.
// Pipeline (step 2): main thread = recvfrom + CDC (core 0) -> Ring1 -> SHA thread = SHA + dedup (core 1)
// -> Ring2 -> LZW threads = LZW + output (cores 2 and 3). Ring1 has one producer and one consumer. Ring2 has one
// producer and NUM_LZW_WORKERS consumers (step 5): each worker takes the next waiting chunk and encodes it into
// that slot's own output buffer; finished records are appended to Output strictly in chunk order, so the
// output is unchanged.
// Double buffering (step 3): the SHA thread keeps one batch on the FPGA while it fills the next one in the
// second buffer pair, then collects / dedups the previous batch while the kernel runs (no q.finish() per batch).
// Kernel: sha_kernel.cpp (sha256_kernel). Build: see Makefile / u96_v2.cfg.
// Usage:  ./encoder [-b blocksize] [-c] [-r] [-n] <compressed output file> [xclbin]   (xclbin defaults to encoder.xclbin)
//         -n: one chunk at a time on the FPGA (no batching, no double buffering), for comparison

#include "encoder.h"
#include "xcl2.hpp"          // OpenCL utility layer (includes CL/cl2.hpp)

#include <stdio.h>
#include <stdint.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <iostream>
#include <vector>
#include <unordered_map>
#include <chrono>
#include <thread>
#include <mutex>
#include <condition_variable>
#include <pthread.h>
#include <sched.h>
#include "server.h"
#include "stopwatch.h"
#include "sha_kernel.h"

#ifndef NUM_ELEMENTS
#define NUM_ELEMENTS 16384
#endif

#define NUM_PACKETS 8
#define DONE_BIT_L (1 << 7)
#define DONE_BIT_H (1 << 15)

#define CODE_LENGTH 13                  // ceil(log2(MAX_CHUNK)); must match decoder
#define MAX_CHUNK   8192
#define MIN_CHUNK   2048
#define CDC_WINDOW  16
#define CDC_MASK    0x7FF               // ~2 KiB expected past MIN_CHUNK => ~4 KiB average
#define CDC_PRIME   31u

typedef std::vector<uint8_t> bytes;

// ---------------------------------------------------------------- statistics / timers
static uint64_t Total_chunks = 0, Dup_chunks = 0;
static uint64_t Dup_bytes = 0, Uniq_bytes = 0, Lzw_out_bytes = 0;
static stopwatch Push_timer, Sha_timer, Dedup_timer;
static stopwatch Ring_full_timer;       // main thread: handing chunks to the SHA thread (incl. waiting on a full Ring1)
static stopwatch Sha_stage_timer;       // SHA thread: busy time (SHA + dedup + copy into Ring2)
static stopwatch Ring2_full_timer;      // SHA thread: handing chunks to the LZW threads (incl. waiting on a full Ring2)
static stopwatch Fpga_wait_timer;       // SHA thread: time blocked waiting for the FPGA to finish a chunk
static double Max_push_ms = 0;          // longest time one packet kept us from calling recvfrom
static uint64_t Max_push_at = 0;        // input byte offset where that happened

// ---------------------------------------------------------------- output buffer
static bytes Output;                    // appended only by Ring2's in-order drain (under Ring2's lock)

// ================================================================ debug options
//   -c : also hash every chunk in software, compare with the FPGA digest, report mismatches,
//        and use the software digest for dedup (so the output stays correct while debugging)
//   -r : move data with enqueueWriteBuffer/enqueueReadBuffer instead of mapped buffers + migrate
//        (with -c -r the digest buffer is pre-filled with 0xAA before every kernel call)
static bool Check_sha = false, Use_rw = false;
static bool No_overlap = false;         // -n: disable double buffering (one chunk at a time, q.finish() per chunk)
static uint64_t Sha_checked = 0, Sha_mismatch = 0, Sha_repeats = 0, Sha_zero = 0;
static uint8_t Prev_hw[32];

// Software SHA-256 (FIPS 180-4), used only for the -c check.
static const uint32_t K256[64] = {
	0x428a2f98,0x71374491,0xb5c0fbcf,0xe9b5dba5,0x3956c25b,0x59f111f1,0x923f82a4,0xab1c5ed5,
	0xd807aa98,0x12835b01,0x243185be,0x550c7dc3,0x72be5d74,0x80deb1fe,0x9bdc06a7,0xc19bf174,
	0xe49b69c1,0xefbe4786,0x0fc19dc6,0x240ca1cc,0x2de92c6f,0x4a7484aa,0x5cb0a9dc,0x76f988da,
	0x983e5152,0xa831c66d,0xb00327c8,0xbf597fc7,0xc6e00bf3,0xd5a79147,0x06ca6351,0x14292967,
	0x27b70a85,0x2e1b2138,0x4d2c6dfc,0x53380d13,0x650a7354,0x766a0abb,0x81c2c92e,0x92722c85,
	0xa2bfe8a1,0xa81a664b,0xc24b8b70,0xc76c51a3,0xd192e819,0xd6990624,0xf40e3585,0x106aa070,
	0x19a4c116,0x1e376c08,0x2748774c,0x34b0bcb5,0x391c0cb3,0x4ed8aa4a,0x5b9cca4f,0x682e6ff3,
	0x748f82ee,0x78a5636f,0x84c87814,0x8cc70208,0x90befffa,0xa4506ceb,0xbef9a3f7,0xc67178f2
};

#define ROR32(x, n) (((x) >> (n)) | ((x) << (32 - (n))))

static void sha256_block(uint32_t h[8], const uint8_t* p) {
	uint32_t w[64];
	for (int t = 0; t < 16; t++)
		w[t] = ((uint32_t) p[4*t] << 24) | ((uint32_t) p[4*t+1] << 16) |
		       ((uint32_t) p[4*t+2] << 8) | (uint32_t) p[4*t+3];
	for (int t = 16; t < 64; t++) {
		uint32_t s0 = ROR32(w[t-15], 7) ^ ROR32(w[t-15], 18) ^ (w[t-15] >> 3);
		uint32_t s1 = ROR32(w[t-2], 17) ^ ROR32(w[t-2], 19) ^ (w[t-2] >> 10);
		w[t] = w[t-16] + s0 + w[t-7] + s1;
	}
	uint32_t a = h[0], b = h[1], c = h[2], d = h[3];
	uint32_t e = h[4], f = h[5], g = h[6], hh = h[7];
	for (int t = 0; t < 64; t++) {
		uint32_t S1 = ROR32(e, 6) ^ ROR32(e, 11) ^ ROR32(e, 25);
		uint32_t ch = (e & f) ^ (~e & g);
		uint32_t t1 = hh + S1 + ch + K256[t] + w[t];
		uint32_t S0 = ROR32(a, 2) ^ ROR32(a, 13) ^ ROR32(a, 22);
		uint32_t maj = (a & b) ^ (a & c) ^ (b & c);
		uint32_t t2 = S0 + maj;
		hh = g; g = f; f = e; e = d + t1;
		d = c; c = b; b = a; a = t1 + t2;
	}
	h[0] += a; h[1] += b; h[2] += c; h[3] += d;
	h[4] += e; h[5] += f; h[6] += g; h[7] += hh;
}

static void sha256(const uint8_t* data, uint32_t len, uint8_t out[32]) {
	uint32_t h[8] = {0x6a09e667,0xbb67ae85,0x3c6ef372,0xa54ff53a,
	                 0x510e527f,0x9b05688c,0x1f83d9ab,0x5be0cd19};
	uint32_t full = len / 64, rem = len % 64;
	for (uint32_t b = 0; b < full; b++) sha256_block(h, data + 64 * b);

	uint8_t block[64];
	memcpy(block, data + 64 * full, rem);
	block[rem] = 0x80;
	if (rem >= 56) {                      // length field does not fit: need a second block
		memset(block + rem + 1, 0, 63 - rem);
		sha256_block(h, block);
		memset(block, 0, 56);
	} else {
		memset(block + rem + 1, 0, 55 - rem);
	}
	uint64_t bits = (uint64_t) len * 8;
	for (int i = 0; i < 8; i++) block[56 + i] = (bits >> (56 - 8 * i)) & 0xFF;
	sha256_block(h, block);

	for (int i = 0; i < 8; i++) {
		out[4*i]   = h[i] >> 24; out[4*i+1] = h[i] >> 16;
		out[4*i+2] = h[i] >> 8;  out[4*i+3] = h[i];
	}
}


// FPGA digest -> out. With -c, also hash in software, count mismatches and use the software digest
// (so the output stays correct while debugging).
static void check_digest(const uint8_t* d, uint32_t len, const uint8_t hw[32], uint8_t out[32]) {
	if (Check_sha) {
		uint8_t sw[32];
		sha256(d, len, sw);
		Sha_checked++;
		bool zero = true;
		for (int i = 0; i < 32; i++) if (hw[i]) zero = false;
		if (zero) Sha_zero++;
		if (Sha_checked > 1 && memcmp(hw, Prev_hw, 32) == 0) Sha_repeats++;
		memcpy(Prev_hw, hw, 32);
		if (memcmp(hw, sw, 32) != 0) {
			if (Sha_mismatch < 5) {
				printf("SHA MISMATCH chunk %llu len %u\n  hw: ", (unsigned long long) Sha_checked, len);
				for (int i = 0; i < 32; i++) printf("%02x", hw[i]);
				printf("\n  sw: ");
				for (int i = 0; i < 32; i++) printf("%02x", sw[i]);
				printf("\n");
			}
			Sha_mismatch++;
		}
		memcpy(out, sw, 32);
		return;
	}
	memcpy(out, hw, 32);
}

// ================================================================ SHA-256 on the FPGA (OpenCL)
#define NBUF 2                                 // input/output buffer pairs on the FPGA (double buffering)

struct FpgaSha {
	cl::CommandQueue q;
	cl::Kernel       krnl;
	cl::Buffer       in_buf[NBUF], out_buf[NBUF];
	uint8_t*         in_ptr[NBUF]  = {NULL, NULL};   // host mappings of in_buf  (SHA_BATCH_IN_BYTES: lengths + chunk data)
	uint8_t*         out_ptr[NBUF] = {NULL, NULL};   // host mappings of out_buf (SHA_BATCH_OUT_BYTES: 32 bytes per chunk)
	cl::Event        in_ev[NBUF], krnl_ev[NBUF], out_ev[NBUF];   // per buffer pair (double-buffered path)
	bool             out_of_order = false;  // queue created with CL_QUEUE_OUT_OF_ORDER_EXEC_MODE_ENABLE
	uint64_t         kernel_ns = 0;        // sum of kernel execution times (profiling info)
	uint64_t         calls = 0;            // kernel calls (batches)
	uint64_t         chunks = 0;           // chunks hashed on the FPGA
};
static FpgaSha* Fpga = NULL;

static bool overlap_mode() { return !Use_rw && !No_overlap; }

static void opencl_init(const char* xclbin_name) {
	cl_int err;
	auto devices = xcl::get_xil_devices();
	auto fileBuf = xcl::read_binary_file(xclbin_name);
	cl::Program::Binaries bins{{fileBuf.data(), fileBuf.size()}};
	cl::Device device = devices[0];
	cl::Context context;
	OCL_CHECK(err, context = cl::Context(device, NULL, NULL, NULL, &err));

	// Double buffering uses an out-of-order queue so the next chunk's input migration can run while the
	// kernel is busy; explicit event dependencies keep each chunk's migrate -> kernel -> migrate in order.
	// The sequential paths (-r, -n) rely on in-order execution.
	if (overlap_mode()) {
		Fpga->q = cl::CommandQueue(context, device,
				CL_QUEUE_PROFILING_ENABLE | CL_QUEUE_OUT_OF_ORDER_EXEC_MODE_ENABLE, &err);
		if (err == CL_SUCCESS) Fpga->out_of_order = true;
		else printf("out-of-order queue not available (error %d): using an in-order queue\n", err);
	}
	if (!Fpga->out_of_order) {                // braces needed: OCL_CHECK expands to two statements
		OCL_CHECK(err, Fpga->q = cl::CommandQueue(context, device, CL_QUEUE_PROFILING_ENABLE, &err));
	}

	cl::Program program(context, {device}, bins, NULL, &err);
	if (err != CL_SUCCESS) {
		printf("Failed to program the device with %s\n", xclbin_name);
		exit(EXIT_FAILURE);
	}
	OCL_CHECK(err, Fpga->krnl = cl::Kernel(program, "sha256_kernel", &err));

	for (int b = 0; b < NBUF; b++) {
		OCL_CHECK(err, Fpga->in_buf[b]  = cl::Buffer(context, CL_MEM_READ_ONLY,  SHA_BATCH_IN_BYTES,  NULL, &err));
		OCL_CHECK(err, Fpga->out_buf[b] = cl::Buffer(context, CL_MEM_WRITE_ONLY, SHA_BATCH_OUT_BYTES, NULL, &err));
		if (!Use_rw) {
			// input mapped read+write: the SHA thread copies unique chunks back out of it for LZW
			Fpga->in_ptr[b]  = (uint8_t*) Fpga->q.enqueueMapBuffer(Fpga->in_buf[b],  CL_TRUE, CL_MAP_READ | CL_MAP_WRITE, 0, SHA_BATCH_IN_BYTES);
			Fpga->out_ptr[b] = (uint8_t*) Fpga->q.enqueueMapBuffer(Fpga->out_buf[b], CL_TRUE, CL_MAP_READ, 0, SHA_BATCH_OUT_BYTES);
		}
	}

	// kernel arguments: 0 = input_data, 1 = output_digest, 2 = num_chunks (set per call).
	// The sequential paths always use buffer pair 0; the batched path sets 0 and 1 per batch.
	OCL_CHECK(err, err = Fpga->krnl.setArg(0, Fpga->in_buf[0]));
	OCL_CHECK(err, err = Fpga->krnl.setArg(1, Fpga->out_buf[0]));
}

static void opencl_shutdown() {
	cl_int err;
	if (!Use_rw) {
		for (int b = 0; b < NBUF; b++) {
			OCL_CHECK(err, err = Fpga->q.enqueueUnmapMemObject(Fpga->in_buf[b],  Fpga->in_ptr[b]));
			OCL_CHECK(err, err = Fpga->q.enqueueUnmapMemObject(Fpga->out_buf[b], Fpga->out_ptr[b]));
		}
	}
	OCL_CHECK(err, err = Fpga->q.finish());
	delete Fpga;
	Fpga = NULL;
}

static void add_kernel_time(const cl::Event& kev) {
	cl_int err;
	cl_ulong t0 = 0, t1 = 0;
	OCL_CHECK(err, err = kev.getProfilingInfo(CL_PROFILING_COMMAND_START, &t0));
	OCL_CHECK(err, err = kev.getProfilingInfo(CL_PROFILING_COMMAND_END, &t1));
	Fpga->kernel_ns += (t1 - t0);
	Fpga->calls++;
}

// ---------------------------------------------------------------- sequential path (-r, -n)
// Hash one chunk (len <= MAX_CHUNK_SIZE) on the FPGA and wait for it: a batch of one. Uses buffer pair 0.
static void sha256_fpga(const uint8_t* d, uint32_t len, uint8_t out[32]) {
	cl_int err;
	cl::Event kev;
	uint8_t hw[32];
	const uint32_t one = 1;

	OCL_CHECK(err, err = Fpga->krnl.setArg(2, one));
	if (Use_rw) {
		if (Check_sha) {                      // pre-fill the digest with 0xAA: if it is still 0xAA afterwards the kernel never wrote it
			uint8_t sentinel[32];
			memset(sentinel, 0xAA, sizeof sentinel);
			OCL_CHECK(err, err = Fpga->q.enqueueWriteBuffer(Fpga->out_buf[0], CL_TRUE, 0, SHA256_DIGEST_SIZE, sentinel));
		}
		OCL_CHECK(err, err = Fpga->q.enqueueWriteBuffer(Fpga->in_buf[0], CL_TRUE, 0, sizeof len, &len));   // length header
		OCL_CHECK(err, err = Fpga->q.enqueueWriteBuffer(Fpga->in_buf[0], CL_TRUE, SHA_BATCH_HDR_WORDS * 4, len, d));
		OCL_CHECK(err, err = Fpga->q.enqueueTask(Fpga->krnl, NULL, &kev));
		OCL_CHECK(err, err = Fpga->q.enqueueReadBuffer(Fpga->out_buf[0], CL_TRUE, 0, SHA256_DIGEST_SIZE, hw));
	} else {
		((uint32_t*) Fpga->in_ptr[0])[0] = len;                                                  // length header
		memcpy(Fpga->in_ptr[0] + SHA_BATCH_HDR_WORDS * 4, d, len);
		OCL_CHECK(err, err = Fpga->q.enqueueMigrateMemObjects({Fpga->in_buf[0]}, 0));            // host -> device
		OCL_CHECK(err, err = Fpga->q.enqueueTask(Fpga->krnl, NULL, &kev));
		OCL_CHECK(err, err = Fpga->q.enqueueMigrateMemObjects({Fpga->out_buf[0]}, CL_MIGRATE_MEM_OBJECT_HOST));
	}
	Fpga_wait_timer.start();
	OCL_CHECK(err, err = Fpga->q.finish());
	Fpga_wait_timer.stop();
	if (!Use_rw) memcpy(hw, Fpga->out_ptr[0], SHA256_DIGEST_SIZE);

	add_kernel_time(kev);
	Fpga->chunks++;
	check_digest(d, len, hw, out);
}

// ---------------------------------------------------------------- batched, double-buffered path (default)
// One batch per buffer pair: chunk c of the batch is in_ptr[k] + off[c], len[c] bytes; its digest comes back
// at out_ptr[k] + 32 * c.
struct ShaBatch {
	uint32_t n = 0;                                // chunks in the batch
	uint32_t data_words = 0;                       // words of chunk data used so far (after the length header)
	uint32_t off[SHA_BATCH_MAX_CHUNKS];            // byte offset of each chunk in in_ptr[k]
	uint32_t len[SHA_BATCH_MAX_CHUNKS];            // length of each chunk in bytes
};

// Append one chunk to batch k (buffer pair k): length into the header, data word aligned after the previous chunk.
static void batch_add(ShaBatch& B, int k, const uint8_t* d, uint32_t len) {
	uint32_t off = (SHA_BATCH_HDR_WORDS + B.data_words) * 4;
	memcpy(Fpga->in_ptr[k] + off, d, len);
	((uint32_t*) Fpga->in_ptr[k])[B.n] = len;
	B.off[B.n] = off;
	B.len[B.n] = len;
	B.n++;
	B.data_words += (len + 3) / 4;
}

// Start hashing the n chunks already in Fpga->in_ptr[k]; returns without waiting.
static void fpga_submit(int k, uint32_t n) {
	cl_int err;
	// OpenCL captures the argument values at enqueue time, so re-setting them for the next batch is safe
	OCL_CHECK(err, err = Fpga->krnl.setArg(0, Fpga->in_buf[k]));
	OCL_CHECK(err, err = Fpga->krnl.setArg(1, Fpga->out_buf[k]));
	OCL_CHECK(err, err = Fpga->krnl.setArg(2, n));
	OCL_CHECK(err, err = Fpga->q.enqueueMigrateMemObjects({Fpga->in_buf[k]}, 0, NULL, &Fpga->in_ev[k]));
	std::vector<cl::Event> after_in{Fpga->in_ev[k]};
	OCL_CHECK(err, err = Fpga->q.enqueueTask(Fpga->krnl, &after_in, &Fpga->krnl_ev[k]));
	std::vector<cl::Event> after_krnl{Fpga->krnl_ev[k]};
	OCL_CHECK(err, err = Fpga->q.enqueueMigrateMemObjects({Fpga->out_buf[k]}, CL_MIGRATE_MEM_OBJECT_HOST,
			&after_krnl, &Fpga->out_ev[k]));
	OCL_CHECK(err, err = Fpga->q.flush());     // send the commands to the device now
}

// Wait for buffer pair k's batch; afterwards its digests are at out_ptr[k] (read them with batch_digest).
static void fpga_wait(int k, uint32_t n) {
	cl_int err;
	Fpga_wait_timer.start();
	OCL_CHECK(err, err = Fpga->out_ev[k].wait());
	Fpga_wait_timer.stop();
	add_kernel_time(Fpga->krnl_ev[k]);
	Fpga->chunks += n;
}

// Digest of chunk c of the finished batch in buffer pair k.
static void batch_digest(const ShaBatch& B, int k, uint32_t c, uint8_t out[32]) {
	uint8_t hw[32];
	memcpy(hw, Fpga->out_ptr[k] + SHA256_DIGEST_SIZE * c, SHA256_DIGEST_SIZE);
	check_digest(Fpga->in_ptr[k] + B.off[c], B.len[c], hw, out);
}

// ================================================================ dedup
struct Digest {
	uint8_t b[32];
	bool operator==(const Digest& o) const { return memcmp(b, o.b, 32) == 0; }
};
struct DigestHash {                       // digest bytes are already uniformly random
	size_t operator()(const Digest& d) const { size_t h; memcpy(&h, d.b, sizeof h); return h; }
};
static std::unordered_map<Digest, uint32_t, DigestHash> Seen;
static uint32_t Next_index = 0;           // index among LZW (unique) chunks only

// returns index of earlier identical chunk, or -1
static int64_t dedup_lookup(const Digest& d) {
	auto it = Seen.find(d);
	return (it == Seen.end()) ? -1 : (int64_t) it->second;
}
static void dedup_insert(const Digest& d) { Seen[d] = Next_index++; }

// ================================================================ LZW
// Dictionary: open-addressed hash table keyed by (prefix_code << 8 | next_byte).
// A generation counter "clears" it per chunk without touching the memory.
// Each LZW worker thread has its own dictionary and statistics (struct LzwWorker), so workers share nothing
// while encoding.
#define LZW_MAX_CODES   (1 << CODE_LENGTH)      // codes 0..8191
#define LZW_TABLE_BITS  14                      // 16384 slots, load <= 0.5
#define LZW_TABLE_SIZE  (1 << LZW_TABLE_BITS)
#define LZW_OUT_MAX     (4 + (CODE_LENGTH * MAX_CHUNK + 7) / 8)   // 13316 bytes

#define NUM_LZW_WORKERS 2                       // LZW threads, pinned to cores 2 .. 2 + NUM_LZW_WORKERS - 1

struct LzwEntry { uint32_t gen; uint32_t key; uint16_t code; };

struct LzwWorker {                              // everything one LZW thread owns
	LzwEntry  table[LZW_TABLE_SIZE];            // gen 0 = never used
	uint32_t  gen = 0;
	uint64_t  uniq_bytes = 0, out_bytes = 0;    // summed into Uniq_bytes / Lzw_out_bytes after join()
	stopwatch lzw_timer;                        // lzw_encode only
	stopwatch stage_timer;                      // busy: encode + hand the record back to Ring2 (in-order append)
	uint64_t  chunks = 0;                       // records produced (unique + duplicate)
};
static LzwWorker Lzw_workers[NUM_LZW_WORKERS];

static inline uint32_t lzw_slot(uint32_t key) {
	return (key * 2654435761u) >> (32 - LZW_TABLE_BITS);
}
static int lzw_find(const LzwWorker& W, uint32_t key) {
	uint32_t s = lzw_slot(key);
	while (W.table[s].gen == W.gen) {
		if (W.table[s].key == key) return W.table[s].code;
		s = (s + 1) & (LZW_TABLE_SIZE - 1);
	}
	return -1;
}
static void lzw_insert(LzwWorker& W, uint32_t key, uint16_t code) {
	uint32_t s = lzw_slot(key);
	while (W.table[s].gen == W.gen) s = (s + 1) & (LZW_TABLE_SIZE - 1);
	W.table[s].gen = W.gen; W.table[s].key = key; W.table[s].code = code;
}

struct BitWriter { uint8_t* out; uint32_t pos; uint32_t acc; int nbits; };

static inline void put_code(BitWriter& w, uint32_t code) {   // MSB-first packing
	w.acc = (w.acc << CODE_LENGTH) | code;
	w.nbits += CODE_LENGTH;
	while (w.nbits >= 8) {
		w.out[w.pos++] = (w.acc >> (w.nbits - 8)) & 0xFF;
		w.nbits -= 8;
	}
	w.acc &= (1u << w.nbits) - 1;
}

// Writes [32b header][packed codes] to out (>= LZW_OUT_MAX bytes). Returns total bytes written.
static uint32_t lzw_encode(LzwWorker& W, const uint8_t* in, uint32_t len, uint8_t* out) {
	if (len == 0) return 0;
	W.gen++;
	BitWriter w = {out, 4, 0, 0};                 // leave 4 bytes for the header
	uint32_t next_code = 256;
	uint32_t prefix = in[0];

	for (uint32_t i = 1; i < len; i++) {
		uint32_t c = in[i];
		uint32_t key = (prefix << 8) | c;
		int code = lzw_find(W, key);
		if (code >= 0) {
			prefix = code;
		} else {
			put_code(w, prefix);
			if (next_code < LZW_MAX_CODES)        // dictionary full: stop adding (decoder never refers past it)
				lzw_insert(W, key, next_code++);
			prefix = c;
		}
	}
	put_code(w, prefix);
	if (w.nbits > 0) w.out[w.pos++] = (w.acc << (8 - w.nbits)) & 0xFF;   // pad to byte

	uint32_t header = (w.pos - 4) << 1;           // bit0 = 0: LZW chunk, bits 31..1 = length in bytes
	for (int i = 0; i < 4; i++) out[i] = (header >> (8 * i)) & 0xFF;
	return w.pos;
}

// ================================================================ per-chunk path

// SHA thread: decide duplicate / unique from the digest. Must run in chunk order (Next_index).
static bool dedup_chunk(const Digest& dg, uint32_t len, uint32_t* dup_idx) {
	Total_chunks++;

	Dedup_timer.start();
	int64_t idx = dedup_lookup(dg);
	if (idx < 0) dedup_insert(dg);
	Dedup_timer.stop();

	if (idx >= 0) {
		Dup_chunks++;
		Dup_bytes += len;
		*dup_idx = (uint32_t) idx;
		return true;
	}
	return false;
}

// SHA thread, sequential path: hash on the FPGA (waiting for it), then dedup.
static bool sha_dedup_chunk(const uint8_t* d, uint32_t len, uint32_t* dup_idx) {
	Digest dg;
	Sha_timer.start();
	sha256_fpga(d, len, dg.b);
	Sha_timer.stop();
	return dedup_chunk(dg, len, dup_idx);
}

// LZW thread: build the chunk's output record in out (>= LZW_OUT_MAX bytes); returns its length.
// Ring2 appends the records to Output in chunk order.
static uint32_t lzw_record(LzwWorker& W, const uint8_t* d, uint32_t len, bool dup, uint32_t dup_idx, uint8_t* out) {
	if (dup) {
		uint32_t v = (dup_idx << 1) | 1;          // bit0 = 1: duplicate of LZW chunk dup_idx
		for (int i = 0; i < 4; i++) out[i] = (v >> (8 * i)) & 0xFF;   // little endian (matches decoder on ARM/x86)
		return 4;
	}
	W.lzw_timer.start();
	uint32_t n = lzw_encode(W, d, len, out);
	W.lzw_timer.stop();
	W.uniq_bytes += len;
	W.out_bytes += n;
	return n;
}

// ================================================================ Chunk Ring buffer

#define RING_SIZE 64                     // > SHA_BATCH_MAX_CHUNKS, so Ring2 can absorb a whole batch

struct ChunkSlot {                       // Ring1: CDC -> SHA thread
	uint8_t data[MAX_CHUNK];
	uint32_t len = 0;
};

struct ChunkRing {
	ChunkSlot slots[RING_SIZE];
	size_t head = 0;                    // consumer read index
	size_t tail = 0;                    // producer write index
	size_t count = 0;                   // number of ready chunks in ring
	bool   done = false;
	std::mutex mtx;
	std::condition_variable cv_not_empty;
	std::condition_variable cv_not_full;

	// called by the producer (CDC) after filling slots[tail]
	void commit_and_advance() {
		std::unique_lock<std::mutex> lock(mtx);
		tail = (tail + 1) % RING_SIZE;
		count++;
		cv_not_empty.notify_one(); // notifies consumer
		cv_not_full.wait(lock, [&] { return count < RING_SIZE; }); 
	}

	// called by the consumer (SHA thread), returns slot index to process
	int acquire_read() {
		std::unique_lock<std::mutex> lock(mtx);
		cv_not_empty.wait(lock, [&] { return count > 0 || done; }); // put consumer to sleep if false condition
		if (count == 0 && done) return -1;
		return (int) head;
	}

	// called by the consumer once it has finished reading slots[idx]
	void release_read() {
		std::unique_lock<std::mutex> lock(mtx);
		head = (head + 1) % RING_SIZE;
		count--;
		cv_not_full.notify_one(); // releases lock, notifies producer
	}

	// called by the producer when no more chunks will come
	void finish() {
		{
			std::lock_guard<std::mutex> lock(mtx);
			done = true;
		}
		cv_not_empty.notify_all();
	}

};

static ChunkRing Ring1;                  // CDC (main thread)        -> SHA + dedup (SHA thread)

// Ring2: SHA thread -> NUM_LZW_WORKERS LZW threads, records leave in chunk order.
// Slot life cycle: the SHA thread fills slots[tail] and commits it; a worker claims it (claim_next), encodes
// into its out[] and calls finish_slot; finish_slot appends every finished slot at the front (head) to Output,
// in order, and only then frees it. A slot is never reused before its record is in Output.
struct Ring2Slot {
	uint8_t  data[MAX_CHUNK];
	uint32_t len = 0;
	bool     dup = false;                 // chunk is a duplicate (data not copied)
	uint32_t dup_idx = 0;                 // index of the earlier LZW chunk
	uint8_t  out[LZW_OUT_MAX + 16];       // this chunk's output record, written by the worker that claimed it
	uint32_t out_len = 0;
	bool     encoded = false;             // out[] complete (set under mtx)
};

struct LzwRing {
	Ring2Slot slots[RING_SIZE];
	size_t head = 0;                    // oldest slot whose record is not yet in Output
	size_t claim = 0;                   // next committed slot to hand to a worker
	size_t tail = 0;                    // producer write index
	size_t count = 0;                   // slots in use: committed and not yet appended to Output
	size_t unclaimed = 0;               // committed slots no worker has taken yet
	bool   done = false;
	std::mutex mtx;
	std::condition_variable cv_work;      // workers: a slot was committed, or done
	std::condition_variable cv_not_full;  // producer: a slot was freed

	// producer (SHA thread) after filling slots[tail]; same interface as ChunkRing
	void commit_and_advance() {
		std::unique_lock<std::mutex> lock(mtx);
		slots[tail].encoded = false;
		tail = (tail + 1) % RING_SIZE;
		count++;
		unclaimed++;
		cv_work.notify_one();
		cv_not_full.wait(lock, [&] { return count < RING_SIZE; });   // slots[tail] free for the next chunk
	}

	// worker: take the next committed slot; -1 when the producer is done and nothing is left
	int claim_next() {
		std::unique_lock<std::mutex> lock(mtx);
		cv_work.wait(lock, [&] { return unclaimed > 0 || done; });
		if (unclaimed == 0) return -1;
		int i = (int) claim;
		claim = (claim + 1) % RING_SIZE;
		unclaimed--;
		return i;
	}

	// worker: slots[i].out is ready. Append every finished slot at the front to Output (chunk order), free them.
	void finish_slot(int i) {
		std::unique_lock<std::mutex> lock(mtx);
		slots[i].encoded = true;
		bool freed = false;
		while (count > 0 && slots[head].encoded) {
			const Ring2Slot& s = slots[head];
			Output.insert(Output.end(), s.out, s.out + s.out_len);
			head = (head + 1) % RING_SIZE;
			count--;
			freed = true;
		}
		if (freed) cv_not_full.notify_one();
	}

	// producer: no more chunks
	void finish() {
		{
			std::lock_guard<std::mutex> lock(mtx);
			done = true;
		}
		cv_work.notify_all();
	}
};
static LzwRing Ring2;

// ================================================================ CDC
// Streaming: state persists across packets so chunks may span packet boundaries.
static uint8_t  Chunk_buf[MAX_CHUNK];
static uint32_t Chunk_len = 0;
static uint32_t Roll = 0;
static uint32_t Prime_pow_w = 1;              // CDC_PRIME^CDC_WINDOW

static void cdc_init() {
	Prime_pow_w = 1;
	for (int i = 0; i < CDC_WINDOW; i++) Prime_pow_w *= CDC_PRIME;
	Chunk_len = 0;
	Roll = 0;
}

static void cdc_emit() {
	// hand the chunk to the worker thread; Chunk_buf is reused right away, so copy it into the ring
	ChunkSlot& s = Ring1.slots[Ring1.tail];   // always free: commit_and_advance() waits until it is
	memcpy(s.data, Chunk_buf, Chunk_len);
	s.len = Chunk_len;
	Ring_full_timer.start();
	Ring1.commit_and_advance();               // blocks only while the ring is full
	Ring_full_timer.stop();
	Chunk_len = 0;
	Roll = 0;
}

static void cdc_push(const uint8_t* in, uint32_t n) {
	for (uint32_t i = 0; i < n; i++) {
		uint8_t b = in[i];
		Roll = Roll * CDC_PRIME + b;
		if (Chunk_len >= CDC_WINDOW)          // remove byte leaving the window
			Roll -= Prime_pow_w * Chunk_buf[Chunk_len - CDC_WINDOW];
		Chunk_buf[Chunk_len++] = b;

		if (Chunk_len == MAX_CHUNK ||
		    (Chunk_len >= MIN_CHUNK && (Roll & CDC_MASK) == 0))
			cdc_emit();
	}
}

static void cdc_flush() {
	if (Chunk_len > 0) cdc_emit();
}

// ================================================================ pipeline stages 2 and 3
// Ownership (no locks needed beyond the rings; main reads everything after join()):
//   SHA thread: OpenCL queue (Fpga), Seen, Next_index, Total/Dup counters, Sha/Dedup timers, -c state
//   LZW threads: their own LzwWorker (dictionary, counters, timers) and the Ring2 slot they claimed;
//                Output is appended only inside Ring2.finish_slot (under Ring2's lock)
// Sequential (-r, -n): one chunk on the FPGA at a time.
static void sha_worker_seq() {
	for (;;) {
		int idx = Ring1.acquire_read();
		if (idx < 0) break;                   // Ring1 finished and empty
		Sha_stage_timer.start();
		const ChunkSlot& in = Ring1.slots[idx];
		Ring2Slot& out = Ring2.slots[Ring2.tail];   // always free: commit_and_advance() waits until it is
		out.dup = sha_dedup_chunk(in.data, in.len, &out.dup_idx);
		out.len = in.len;
		if (!out.dup) memcpy(out.data, in.data, in.len);   // duplicates only need the index
		Sha_stage_timer.stop();
		Ring1.release_read();                 // done with the Ring1 slot: CDC can reuse it
		Ring2_full_timer.start();
		Ring2.commit_and_advance();           // blocks only while Ring2 is full
		Ring2_full_timer.stop();
	}
	Ring2.finish();                           // tell the LZW threads no more chunks are coming
}

// Batched + double-buffered (default). Iteration i: fill batch i (buffer pair i%2) from Ring1 until it holds
// SHA_BATCH_MAX_CHUNKS chunks or Ring1 is finished, submit it, then collect batch i-1 (buffer pair (i-1)%2):
// dedup its chunks in order and hand them to the LZW thread while batch i runs on the FPGA.
// Buffer pair i%2 is free when batch i is filled: its previous batch (i-2) was collected in iteration i-1.
static ShaBatch Batch[NBUF];

static void collect_batch(int k) {           // SHA thread: finish batch k, dedup it, push its chunks to Ring2
	const ShaBatch& B = Batch[k];
	Sha_stage_timer.start();
	Sha_timer.start();
	fpga_wait(k, B.n);
	Sha_timer.stop();
	Sha_stage_timer.stop();
	for (uint32_t c = 0; c < B.n; c++) {
		Sha_stage_timer.start();
		Digest dg;
		Sha_timer.start();
		batch_digest(B, k, c, dg.b);
		Sha_timer.stop();
		Ring2Slot& out = Ring2.slots[Ring2.tail];   // always free: commit_and_advance() waits until it is
		out.len = B.len[c];
		out.dup = dedup_chunk(dg, out.len, &out.dup_idx);
		if (!out.dup) memcpy(out.data, Fpga->in_ptr[k] + B.off[c], out.len);   // the kernel only reads in_buf
		Sha_stage_timer.stop();
		Ring2_full_timer.start();
		Ring2.commit_and_advance();           // blocks only while Ring2 is full
		Ring2_full_timer.stop();
	}
}

static void sha_worker_overlap() {
	int k = 0;                                // buffer pair for the next batch
	int prev = -1;                            // buffer pair of the batch in flight, or -1
	bool finished = false;
	while (!finished) {
		ShaBatch& B = Batch[k];
		B.n = 0;
		B.data_words = 0;
		while (B.n < SHA_BATCH_MAX_CHUNKS) {  // fill the batch
			int idx = Ring1.acquire_read();
			if (idx < 0) { finished = true; break; }   // Ring1 finished and empty
			Sha_stage_timer.start();
			Sha_timer.start();
			batch_add(B, k, Ring1.slots[idx].data, Ring1.slots[idx].len);
			Sha_timer.stop();
			Sha_stage_timer.stop();
			Ring1.release_read();             // the chunk now lives in the FPGA buffer: CDC can reuse the slot
		}
		bool submitted = B.n > 0;
		if (submitted) {
			Sha_stage_timer.start();
			Sha_timer.start();
			fpga_submit(k, B.n);
			Sha_timer.stop();
			Sha_stage_timer.stop();
		}
		if (prev >= 0) collect_batch(prev);   // previous batch: finishes on the FPGA, then dedup + hand to LZW
		prev = submitted ? k : -1;
		k = (k + 1) % NBUF;
	}
	if (prev >= 0) collect_batch(prev);       // last batch
	Ring2.finish();                           // tell the LZW threads no more chunks are coming
}

static void lzw_worker(int id) {
	LzwWorker& W = Lzw_workers[id];
	for (;;) {
		int idx = Ring2.claim_next();
		if (idx < 0) break;                   // Ring2 finished and every chunk claimed
		W.stage_timer.start();
		Ring2Slot& s = Ring2.slots[idx];
		s.out_len = lzw_record(W, s.data, s.len, s.dup, s.dup_idx, s.out);
		W.chunks++;
		Ring2.finish_slot(idx);               // in-order append to Output (may append other workers' records too)
		W.stage_timer.stop();
	}
}

static void pin_to_cpu(pthread_t t, int cpu) {    // as in HW3 Utilities.cpp
	cpu_set_t cpuset;
	CPU_ZERO(&cpuset);
	CPU_SET(cpu, &cpuset);
	int rc = pthread_setaffinity_np(t, sizeof(cpu_set_t), &cpuset);
	if (rc != 0) printf("pthread_setaffinity_np(cpu %d) failed: %d\n", cpu, rc);
}

// ================================================================ main / input
void handle_input(int argc, char* argv[], int* blocksize, const char** outname, const char** xclbin) {
	int x;
	extern char *optarg;
	extern int optind;

	while ((x = getopt(argc, argv, ":b:crn")) != -1) {
		switch (x) {
		case 'b':
			*blocksize = atoi(optarg);
			printf("blocksize is set to %d optarg\n", *blocksize);
			break;
		case 'c':
			Check_sha = true;
			printf("checking FPGA SHA-256 against software (-c)\n");
			break;
		case 'r':
			Use_rw = true;
			printf("using enqueueWriteBuffer/ReadBuffer (-r)\n");
			break;
		case 'n':
			No_overlap = true;
			printf("double buffering off: one chunk at a time on the FPGA (-n)\n");
			break;
		case ':':
			printf("-%c without parameter\n", optopt);
			break;
		}
	}
	if (optind < argc) *outname = argv[optind];   // one argument: compressed output file
	if (optind + 1 < argc) *xclbin = argv[optind + 1];   // optional: xclbin path
}

int main(int argc, char* argv[]) {
	stopwatch ethernet_timer;
	stopwatch total_timer;
	stopwatch opencl_timer;
	unsigned char* input[NUM_PACKETS];
	int writer = 0;
	int done = 0;
	int length = 0;
	uint64_t bytes_in = 0;
	ESE532_Server server;

	int blocksize = BLOCKSIZE;
	const char* outname = "output_cpu.bin";
	const char* xclbin = "encoder.xclbin";       // expected next to the executable
	handle_input(argc, argv, &blocksize, &outname, &xclbin);

	for (int i = 0; i < NUM_PACKETS; i++) {
		input[i] = (unsigned char*) malloc(sizeof(unsigned char) * (NUM_ELEMENTS + HEADER));
		if (input[i] == NULL) {
			std::cout << "aborting " << std::endl;
			return 1;
		}
	}

	Fpga = new FpgaSha();
	opencl_timer.start();
	opencl_init(xclbin);                      // program FPGA, create buffers (not part of the timed run)
	opencl_timer.stop();

	Output.reserve((size_t) 1 << 28);   // 256 MiB up front: avoids a mid-run realloc/copy stall
	cdc_init();
	server.setup_server(blocksize);

	std::thread sha_thread(overlap_mode() ? sha_worker_overlap : sha_worker_seq);   // stage 2: SHA + dedup
	std::vector<std::thread> lzw_threads;     // pipeline stage 3: LZW + output, cores 2, 3, ...
	for (int i = 0; i < NUM_LZW_WORKERS; i++) lzw_threads.emplace_back(lzw_worker, i);
	pin_to_cpu(pthread_self(), 0);            // this thread: recvfrom + CDC
	pin_to_cpu(sha_thread.native_handle(), 1);
	for (int i = 0; i < NUM_LZW_WORKERS; i++) pin_to_cpu(lzw_threads[i].native_handle(), 2 + i);

	bool first_packet = true;
	while (!done) {
		if (!first_packet) ethernet_timer.start();
		server.get_packet(input[writer]);
		if (!first_packet) ethernet_timer.stop();
		if (first_packet) {                  // clocks start once data is actually flowing
			total_timer.start();
			first_packet = false;
		}

		unsigned char* buffer = input[writer];
		done = buffer[1] & DONE_BIT_L;
		length = buffer[0] | (buffer[1] << 8);
		length &= ~DONE_BIT_H;

		auto t0 = std::chrono::steady_clock::now();
		Push_timer.start();
		cdc_push(&buffer[HEADER], length);    // CDC -> SHA -> dedup -> LZW
		Push_timer.stop();
		double ms = std::chrono::duration<double, std::milli>(
				std::chrono::steady_clock::now() - t0).count();
		if (ms > Max_push_ms) { Max_push_ms = ms; Max_push_at = bytes_in; }
		bytes_in += length;

		writer = (writer + 1) % NUM_PACKETS;
	}
	Push_timer.start();
	cdc_flush();                              // last (possibly short) chunk
	Push_timer.stop();
	Ring1.finish();                           // no more chunks: SHA thread drains Ring1, then finishes Ring2
	sha_thread.join();
	for (auto& t : lzw_threads) t.join();     // LZW threads drain Ring2 and exit
	total_timer.stop();
	for (int i = 0; i < NUM_LZW_WORKERS; i++) {
		Uniq_bytes    += Lzw_workers[i].uniq_bytes;
		Lzw_out_bytes += Lzw_workers[i].out_bytes;
	}

	FILE *outfd = fopen(outname, "wb");
	if (outfd == NULL) { printf("cannot open %s\n", outname); return 1; }
	size_t bytes_written = fwrite(Output.data(), 1, Output.size(), outfd);
	int close_err = fclose(outfd);
	if (bytes_written != Output.size() || close_err != 0)
		printf("ERROR: short write to %s: wrote %zu of %zu bytes (disk full?)\n",
		       outname, bytes_written, Output.size());

	// ---------------- report
	double dup_hdr_bytes = 4.0 * Dup_chunks;
	printf("--------------- Compression ---------------\n");
	printf("input bytes            : %llu\n", (unsigned long long) bytes_in);
	printf("output bytes           : %zu\n", bytes_written);
	printf("overall ratio (in/out) : %.3f\n", bytes_written ? (double) bytes_in / bytes_written : 0.0);
	printf("chunks                 : %llu total, %llu duplicate\n",
	       (unsigned long long) Total_chunks, (unsigned long long) Dup_chunks);
	printf("dedup:  %llu duplicate bytes -> %.0f header bytes; after dedup %.0f bytes (ratio %.3f)\n",
	       (unsigned long long) Dup_bytes, dup_hdr_bytes,
	       (double) Uniq_bytes + dup_hdr_bytes,
	       bytes_in ? (double) bytes_in / ((double) Uniq_bytes + dup_hdr_bytes) : 0.0);
	printf("LZW:    %llu unique bytes -> %llu bytes incl. headers (ratio %.3f)\n",
	       (unsigned long long) Uniq_bytes, (unsigned long long) Lzw_out_bytes,
	       Lzw_out_bytes ? (double) Uniq_bytes / Lzw_out_bytes : 0.0);

	float sha_ms = Sha_timer.latency(), dedup_ms = Dedup_timer.latency();
	float handoff_ms = Ring_full_timer.latency();
	float cdc_ms = Push_timer.latency() - handoff_ms;          // main thread, CDC only
	float sha_stage_ms = Sha_stage_timer.latency();            // SHA thread busy time
	float lzw_stage_ms = 0;                                    // busiest LZW thread (they run in parallel)
	for (int i = 0; i < NUM_LZW_WORKERS; i++)
		if (Lzw_workers[i].stage_timer.latency() > lzw_stage_ms) lzw_stage_ms = Lzw_workers[i].stage_timer.latency();
	float compute_ms = cdc_ms;                                 // stages overlap: the slowest one bounds throughput
	if (sha_stage_ms > compute_ms) compute_ms = sha_stage_ms;
	if (lzw_stage_ms > compute_ms) compute_ms = lzw_stage_ms;
	printf("--------------- Time breakdown (ms) ---------------\n");
	printf("main thread: CDC %.2f | hand-off to SHA thread (incl. waiting on full Ring1) %.2f\n", cdc_ms, handoff_ms);
	printf("SHA thread : SHA-256 %.2f | dedup %.2f | busy %.2f | hand-off to LZW threads (incl. waiting on full Ring2) %.2f\n",
	       sha_ms, dedup_ms, sha_stage_ms, Ring2_full_timer.latency());
	for (int i = 0; i < NUM_LZW_WORKERS; i++)
		printf("LZW thread %d (core %d): LZW %.2f | busy %.2f | %llu chunks\n", i, 2 + i,
		       Lzw_workers[i].lzw_timer.latency(), Lzw_workers[i].stage_timer.latency(),
		       (unsigned long long) Lzw_workers[i].chunks);
	printf("end-to-end (first packet to last chunk processed): %.2f ms\n", total_timer.latency());
	printf("SHA-256 on FPGA: %llu kernel calls for %llu chunks (%.1f chunks/call), kernel execution %.2f ms total (%.1f us avg per call, %.1f us per chunk); host-side SHA time above includes copies and OpenCL overhead\n",
	       (unsigned long long) Fpga->calls, (unsigned long long) Fpga->chunks,
	       Fpga->calls ? (double) Fpga->chunks / Fpga->calls : 0.0, Fpga->kernel_ns / 1e6,
	       Fpga->calls ? Fpga->kernel_ns / 1e3 / Fpga->calls : 0.0,
	       Fpga->chunks ? Fpga->kernel_ns / 1e3 / Fpga->chunks : 0.0);
	printf("SHA mode: %s | SHA thread waited on the FPGA %.2f ms\n",
	       Use_rw ? "sequential (-r)" : No_overlap ? "sequential (-n)" :
	       Fpga->out_of_order ? "batched + double-buffered, out-of-order queue" : "batched + double-buffered, in-order queue",
	       Fpga_wait_timer.latency());
	if (overlap_mode()) printf("SHA batch size: up to %d chunks per kernel call\n", SHA_BATCH_MAX_CHUNKS);
	printf("OpenCL setup (excluded from run time): %.2f ms\n", opencl_timer.latency());
	if (Check_sha)
		printf("SHA check: %llu of %llu FPGA digests differ from software (%llu all-zero, %llu identical to the previous digest)\n",
		       (unsigned long long) Sha_mismatch, (unsigned long long) Sha_checked,
		       (unsigned long long) Sha_zero, (unsigned long long) Sha_repeats);

	printf("longest single-packet processing: %.2f ms (at input offset %llu)\n",
	       Max_push_ms, (unsigned long long) Max_push_at);

	std::cout << "--------------- Key Throughputs ---------------" << std::endl;
	float ethernet_latency = ethernet_timer.latency() / 1000.0;
	float input_throughput = (bytes_in * 8 / 1000000.0) / ethernet_latency; // Mb/s
	std::cout << "Input Throughput to Encoder: " << input_throughput << " Mb/s."
			<< " (Latency: " << ethernet_latency << "s)." << std::endl;
	if (compute_ms > 0)
		std::cout << "Compute-only throughput (slowest stage): "
				<< (bytes_in * 8 / 1000000.0) / (compute_ms / 1000.0) << " Mb/s." << std::endl;

	if (total_timer.latency() > 0)
		std::cout << "End-to-end throughput      : "
				<< (bytes_in * 8 / 1000000.0) / (total_timer.latency() / 1000.0) << " Mb/s." << std::endl;

	opencl_shutdown();
	for (int i = 0; i < NUM_PACKETS; i++) free(input[i]);
	return 0;
}
