// ESE5320 Project - encoder host code, SHA-256 on the FPGA (FPGA milestone, baseline)
//
// Flow:  Ethernet packets -> CDC (ARM) -> SHA-256 (FPGA kernel, OpenCL) -> dedup (ARM)
//                                                 -+-> duplicate header
//                                                  +-> LZW (ARM) -> output buffer -> file
//
// One kernel call per chunk (copy in, run, copy out, wait).
// Buffers are mapped once at setup; each call only migrates them (Vitis tutorial pattern).
// Kernel: hls/sha_kernel.cpp (sha256_kernel). Build: see Makefile / u96_v2.cfg.
// Usage:  ./encoder [-b blocksize] [compressed output file] [xclbin]
//         (defaults: output_fpga.bin, encoder.xclbin)
// Build with -DVERIFY_SHA to check every FPGA digest against software SHA-256.

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
#define MAX_CHUNK   MAX_CHUNK_SIZE      // CDC chunks must fit the kernel's input buffer
#define MIN_CHUNK   2048
#define CDC_WINDOW  16
#define CDC_MASK    0x7FF               // ~2 KiB expected past MIN_CHUNK => ~4 KiB average
#define CDC_PRIME   31u

typedef std::vector<uint8_t> bytes;

// ---------------------------------------------------------------- statistics / timers
static uint64_t Total_chunks = 0, Dup_chunks = 0;
static uint64_t Dup_bytes = 0, Uniq_bytes = 0, Lzw_out_bytes = 0;
static stopwatch Push_timer, Sha_timer, Dedup_timer, Lzw_timer;
static double Max_push_ms = 0;          // longest time one packet kept us from calling recvfrom
static uint64_t Max_push_at = 0;        // input byte offset where that happened

// ---------------------------------------------------------------- output buffer
static bytes Output;

static void put_u32(uint32_t v) {       // headers are little endian (matches decoder on ARM/x86)
	for (int i = 0; i < 4; i++) Output.push_back((v >> (8 * i)) & 0xFF);
}

// ================================================================ SHA-256 on the FPGA (OpenCL)
struct FpgaSha {
	cl::CommandQueue q;
	cl::Kernel       krnl;
	cl::Buffer       in_buf, out_buf;
	uint8_t*         in_ptr  = NULL;       // host mapping of in_buf  (<= MAX_CHUNK_SIZE bytes)
	uint8_t*         out_ptr = NULL;       // host mapping of out_buf (32-byte digest)
	uint64_t         kernel_ns = 0;        // sum of kernel execution times (profiling info)
	uint64_t         calls = 0;
};
static FpgaSha* Fpga = NULL;

static void opencl_init(const char* xclbin_name) {
	cl_int err;
	auto devices = xcl::get_xil_devices();
	if (devices.empty()) {
		printf("No Xilinx device found\n");
		exit(EXIT_FAILURE);
	}
	auto fileBuf = xcl::read_binary_file(xclbin_name);
	cl::Program::Binaries bins{{fileBuf.data(), fileBuf.size()}};
	cl::Device device = devices[0];
	cl::Context context;
	OCL_CHECK(err, context = cl::Context(device, NULL, NULL, NULL, &err));
	OCL_CHECK(err, Fpga->q = cl::CommandQueue(context, device, CL_QUEUE_PROFILING_ENABLE, &err));
	cl::Program program(context, {device}, bins, NULL, &err);
	if (err != CL_SUCCESS) {
		printf("Failed to program the device with %s\n", xclbin_name);
		exit(EXIT_FAILURE);
	}
	OCL_CHECK(err, Fpga->krnl = cl::Kernel(program, "sha256_kernel", &err));

	OCL_CHECK(err, Fpga->in_buf  = cl::Buffer(context, CL_MEM_READ_ONLY,  MAX_CHUNK_SIZE,     NULL, &err));
	OCL_CHECK(err, Fpga->out_buf = cl::Buffer(context, CL_MEM_WRITE_ONLY, SHA256_DIGEST_SIZE, NULL, &err));
	// Map once for the whole run. Each call then only migrates the buffers, which does the
	// host<->FPGA sync; no per-chunk unmap/re-map is needed.
	OCL_CHECK(err, Fpga->in_ptr = (uint8_t*) Fpga->q.enqueueMapBuffer(
			Fpga->in_buf, CL_TRUE, CL_MAP_WRITE, 0, MAX_CHUNK_SIZE, NULL, NULL, &err));
	OCL_CHECK(err, Fpga->out_ptr = (uint8_t*) Fpga->q.enqueueMapBuffer(
			Fpga->out_buf, CL_TRUE, CL_MAP_READ, 0, SHA256_DIGEST_SIZE, NULL, NULL, &err));

	// kernel arguments: 0 = input_data, 1 = output_digest, 2 = length (set per chunk).
	// The same cl::Buffer objects are used for setArg, mapping and migration.
	OCL_CHECK(err, err = Fpga->krnl.setArg(0, Fpga->in_buf));
	OCL_CHECK(err, err = Fpga->krnl.setArg(1, Fpga->out_buf));
}

static void opencl_shutdown() {
	cl_int err;
	OCL_CHECK(err, err = Fpga->q.enqueueUnmapMemObject(Fpga->in_buf,  Fpga->in_ptr));
	OCL_CHECK(err, err = Fpga->q.enqueueUnmapMemObject(Fpga->out_buf, Fpga->out_ptr));
	OCL_CHECK(err, err = Fpga->q.finish());
	delete Fpga;
	Fpga = NULL;
}

// ================================================================ software SHA-256 (verification only)
#ifdef VERIFY_SHA
static const uint32_t K256_sw[64] = {
	0x428a2f98,0x71374491,0xb5c0fbcf,0xe9b5dba5,0x3956c25b,0x59f111f1,0x923f82a4,0xab1c5ed5,
	0xd807aa98,0x12835b01,0x243185be,0x550c7dc3,0x72be5d74,0x80deb1fe,0x9bdc06a7,0xc19bf174,
	0xe49b69c1,0xefbe4786,0x0fc19dc6,0x240ca1cc,0x2de92c6f,0x4a7484aa,0x5cb0a9dc,0x76f988da,
	0x983e5152,0xa831c66d,0xb00327c8,0xbf597fc7,0xc6e00bf3,0xd5a79147,0x06ca6351,0x14292967,
	0x27b70a85,0x2e1b2138,0x4d2c6dfc,0x53380d13,0x650a7354,0x766a0abb,0x81c2c92e,0x92722c85,
	0xa2bfe8a1,0xa81a664b,0xc24b8b70,0xc76c51a3,0xd192e819,0xd6990624,0xf40e3585,0x106aa070,
	0x19a4c116,0x1e376c08,0x2748774c,0x34b0bcb5,0x391c0cb3,0x4ed8aa4a,0x5b9cca4f,0x682e6ff3,
	0x748f82ee,0x78a5636f,0x84c87814,0x8cc70208,0x90befffa,0xa4506ceb,0xbef9a3f7,0xc67178f2
};
#define ROR32_SW(x, n) (((x) >> (n)) | ((x) << (32 - (n))))
static void sha256_sw_block(uint32_t h[8], const uint8_t* p) {
	uint32_t w[64];
	for (int t = 0; t < 16; t++)
		w[t] = ((uint32_t) p[4*t] << 24) | ((uint32_t) p[4*t+1] << 16) | ((uint32_t) p[4*t+2] << 8) | p[4*t+3];
	for (int t = 16; t < 64; t++)
		w[t] = w[t-16] + (ROR32_SW(w[t-15],7) ^ ROR32_SW(w[t-15],18) ^ (w[t-15] >> 3)) + w[t-7]
		     + (ROR32_SW(w[t-2],17) ^ ROR32_SW(w[t-2],19) ^ (w[t-2] >> 10));
	uint32_t a=h[0],b=h[1],c=h[2],d=h[3],e=h[4],f=h[5],g=h[6],hh=h[7];
	for (int t = 0; t < 64; t++) {
		uint32_t t1 = hh + (ROR32_SW(e,6)^ROR32_SW(e,11)^ROR32_SW(e,25)) + ((e&f)^(~e&g)) + K256_sw[t] + w[t];
		uint32_t t2 = (ROR32_SW(a,2)^ROR32_SW(a,13)^ROR32_SW(a,22)) + ((a&b)^(a&c)^(b&c));
		hh=g; g=f; f=e; e=d+t1; d=c; c=b; b=a; a=t1+t2;
	}
	h[0]+=a; h[1]+=b; h[2]+=c; h[3]+=d; h[4]+=e; h[5]+=f; h[6]+=g; h[7]+=hh;
}
static void sha256_sw(const uint8_t* data, uint32_t len, uint8_t out[32]) {
	uint32_t h[8] = {0x6a09e667,0xbb67ae85,0x3c6ef372,0xa54ff53a,
	                 0x510e527f,0x9b05688c,0x1f83d9ab,0x5be0cd19};
	uint32_t full = len / 64, rem = len % 64;
	for (uint32_t i = 0; i < full; i++) sha256_sw_block(h, data + 64 * i);
	uint8_t b[128] = {0};
	memcpy(b, data + 64 * full, rem);
	b[rem] = 0x80;
	uint32_t total = (rem >= 56) ? 128 : 64;
	uint64_t bits = (uint64_t) len * 8;
	for (int i = 0; i < 8; i++) b[total - 1 - i] = (bits >> (8 * i)) & 0xFF;
	sha256_sw_block(h, b);
	if (total == 128) sha256_sw_block(h, b + 64);
	for (int i = 0; i < 8; i++) {
		out[4*i] = h[i] >> 24; out[4*i+1] = h[i] >> 16; out[4*i+2] = h[i] >> 8; out[4*i+3] = h[i];
	}
}
static uint64_t Sha_mismatches = 0;
#endif

// Hash one chunk (len <= MAX_CHUNK_SIZE) on the FPGA.
static void sha256_fpga(const uint8_t* d, uint32_t len, uint8_t out[32]) {
	if (len > MAX_CHUNK_SIZE) {
		fprintf(stderr, "SHA-256 chunk length %u exceeds buffer capacity %u\n",
		        len, (unsigned) MAX_CHUNK_SIZE);
		exit(EXIT_FAILURE);
	}

	cl_int err;
	cl::Event kev;
	memcpy(Fpga->in_ptr, d, len);
	OCL_CHECK(err, err = Fpga->krnl.setArg(2, len));
	OCL_CHECK(err, err = Fpga->q.enqueueMigrateMemObjects({Fpga->in_buf}, 0));            // host -> device
	OCL_CHECK(err, err = Fpga->q.enqueueTask(Fpga->krnl, NULL, &kev));
	OCL_CHECK(err, err = Fpga->q.enqueueMigrateMemObjects({Fpga->out_buf}, CL_MIGRATE_MEM_OBJECT_HOST));
	OCL_CHECK(err, err = Fpga->q.finish());

	cl_ulong t0 = 0, t1 = 0;
	OCL_CHECK(err, err = kev.getProfilingInfo(CL_PROFILING_COMMAND_START, &t0));
	OCL_CHECK(err, err = kev.getProfilingInfo(CL_PROFILING_COMMAND_END, &t1));
	Fpga->kernel_ns += (t1 - t0);
	Fpga->calls++;

	memcpy(out, Fpga->out_ptr, SHA256_DIGEST_SIZE);

#ifdef VERIFY_SHA
	uint8_t ref[32];
	sha256_sw(d, len, ref);
	if (memcmp(ref, out, 32) != 0 && Sha_mismatches++ < 10)
		printf("SHA mismatch on chunk %llu (len %u)\n", (unsigned long long) Fpga->calls - 1, len);
#endif
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
#define LZW_MAX_CODES   (1 << CODE_LENGTH)      // codes 0..8191
#define LZW_TABLE_BITS  14                      // 16384 slots, load <= 0.5
#define LZW_TABLE_SIZE  (1 << LZW_TABLE_BITS)
#define LZW_OUT_MAX     (4 + (CODE_LENGTH * MAX_CHUNK + 7) / 8)   // 13316 bytes

struct LzwSlot { uint32_t gen; uint32_t key; uint16_t code; };
static LzwSlot  Lzw_table[LZW_TABLE_SIZE];      // gen 0 = never used
static uint32_t Lzw_gen = 0;

static inline uint32_t lzw_slot(uint32_t key) {
	return (key * 2654435761u) >> (32 - LZW_TABLE_BITS);
}
static int lzw_find(uint32_t key) {
	uint32_t s = lzw_slot(key);
	while (Lzw_table[s].gen == Lzw_gen) {
		if (Lzw_table[s].key == key) return Lzw_table[s].code;
		s = (s + 1) & (LZW_TABLE_SIZE - 1);
	}
	return -1;
}
static void lzw_insert(uint32_t key, uint16_t code) {
	uint32_t s = lzw_slot(key);
	while (Lzw_table[s].gen == Lzw_gen) s = (s + 1) & (LZW_TABLE_SIZE - 1);
	Lzw_table[s].gen = Lzw_gen; Lzw_table[s].key = key; Lzw_table[s].code = code;
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
static uint32_t lzw_encode(const uint8_t* in, uint32_t len, uint8_t* out) {
	if (len == 0) return 0;
	Lzw_gen++;
	BitWriter w = {out, 4, 0, 0};                 // leave 4 bytes for the header
	uint32_t next_code = 256;
	uint32_t prefix = in[0];

	for (uint32_t i = 1; i < len; i++) {
		uint32_t c = in[i];
		uint32_t key = (prefix << 8) | c;
		int code = lzw_find(key);
		if (code >= 0) {
			prefix = code;
		} else {
			put_code(w, prefix);
			if (next_code < LZW_MAX_CODES)        // dictionary full: stop adding (decoder never refers past it)
				lzw_insert(key, next_code++);
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
static uint8_t Lzw_buf[LZW_OUT_MAX + 16];

static void process_chunk(const uint8_t* d, uint32_t len) {
	Total_chunks++;

	Digest dg;
	Sha_timer.start();
	sha256_fpga(d, len, dg.b);
	Sha_timer.stop();

	Dedup_timer.start();
	int64_t idx = dedup_lookup(dg);
	Dedup_timer.stop();

	if (idx >= 0) {
		Dup_chunks++;
		Dup_bytes += len;
		put_u32(((uint32_t) idx << 1) | 1);       // bit0 = 1: duplicate of LZW chunk idx
	} else {
		Dedup_timer.start();
		dedup_insert(dg);
		Dedup_timer.stop();

		Lzw_timer.start();
		uint32_t n = lzw_encode(d, len, Lzw_buf);
		Lzw_timer.stop();

		Output.insert(Output.end(), Lzw_buf, Lzw_buf + n);
		Uniq_bytes += len;
		Lzw_out_bytes += n;
	}
}

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
	process_chunk(Chunk_buf, Chunk_len);
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

// ================================================================ main / input
void handle_input(int argc, char* argv[], int* blocksize, const char** outname, const char** xclbin) {
	int x;
	extern char *optarg;
	extern int optind;

	while ((x = getopt(argc, argv, ":b:")) != -1) {
		switch (x) {
		case 'b':
			*blocksize = atoi(optarg);
			printf("blocksize is set to %d optarg\n", *blocksize);
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
	const char* outname = "output_fpga.bin";
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

	// First packet is received before any timer starts: recvfrom blocks here until the
	// client is launched, and that wait is not part of the encoder's run time.
	int packet_bytes = server.get_packet(input[writer]);

	total_timer.start();
	for (;;) {
		if (packet_bytes < HEADER) {
			fprintf(stderr, "received invalid UDP packet length %d\n", packet_bytes);
			return EXIT_FAILURE;
		}

		unsigned char* buffer = input[writer];
		done = buffer[1] & DONE_BIT_L;
		length = buffer[0] | (buffer[1] << 8);
		length &= ~DONE_BIT_H;
		if ((uint32_t) length != (uint32_t) (packet_bytes - HEADER)) {
			fprintf(stderr, "UDP length mismatch: header says %d bytes, received %d\n",
			        length, packet_bytes - HEADER);
			return EXIT_FAILURE;
		}

		auto t0 = std::chrono::steady_clock::now();
		Push_timer.start();
		cdc_push(&buffer[HEADER], length);    // CDC -> SHA -> dedup -> LZW
		Push_timer.stop();
		double ms = std::chrono::duration<double, std::milli>(
				std::chrono::steady_clock::now() - t0).count();
		if (ms > Max_push_ms) { Max_push_ms = ms; Max_push_at = bytes_in; }
		bytes_in += length;

		writer = (writer + 1) % NUM_PACKETS;
		if (done) break;                      // last packet: don't wait for another

		ethernet_timer.start();
		packet_bytes = server.get_packet(input[writer]);
		ethernet_timer.stop();
	}
	Push_timer.start();
	cdc_flush();                              // last (possibly short) chunk
	Push_timer.stop();
	total_timer.stop();

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
#ifdef VERIFY_SHA
	printf("SHA verify: %llu of %llu FPGA digests differ from software\n",
	       (unsigned long long) Sha_mismatches, (unsigned long long) Fpga->calls);
#endif

	float sha_ms = Sha_timer.latency(), dedup_ms = Dedup_timer.latency(), lzw_ms = Lzw_timer.latency();
	float cdc_ms = Push_timer.latency() - sha_ms - dedup_ms - lzw_ms;
	float compute_ms = Push_timer.latency();
	printf("--------------- Time breakdown (ms) ---------------\n");
	printf("CDC %.2f | SHA-256 %.2f | dedup %.2f | LZW %.2f | total compute %.2f\n",
	       cdc_ms, sha_ms, dedup_ms, lzw_ms, compute_ms);
	printf("SHA-256 on FPGA: %llu calls, kernel execution %.2f ms total (%.1f us avg); host-side SHA time above includes copies and OpenCL overhead\n",
	       (unsigned long long) Fpga->calls, Fpga->kernel_ns / 1e6,
	       Fpga->calls ? Fpga->kernel_ns / 1e3 / Fpga->calls : 0.0);
	printf("OpenCL setup (excluded from run time): %.2f ms\n", opencl_timer.latency());

	printf("longest single-packet processing: %.2f ms (at input offset %llu)\n",
	       Max_push_ms, (unsigned long long) Max_push_at);

	// End-to-end: first packet received -> last chunk encoded (file write excluded).
	// Compute-only: time inside CDC/SHA/dedup/LZW, i.e. the rate if the network were infinitely fast.
	// recvfrom time is how long the encoder sat waiting for packets. It is NOT the link rate:
	// while the encoder computes, packets queue in the socket buffer and recvfrom returns at once.
	double total_s = total_timer.latency() / 1000.0;
	printf("--------------- Key Throughputs ---------------\n");
	printf("End-to-end throughput   : %.2f Mb/s (%.3f s)\n",
	       total_s > 0 ? bytes_in * 8 / 1e6 / total_s : 0.0, total_s);
	printf("Compute-only throughput : %.2f Mb/s (%.3f s)\n",
	       compute_ms > 0 ? bytes_in * 8 / 1e6 / (compute_ms / 1000.0) : 0.0, compute_ms / 1000.0);
	printf("Time blocked in recvfrom: %.3f s\n", ethernet_timer.latency() / 1000.0);

	opencl_shutdown();
	for (int i = 0; i < NUM_PACKETS; i++) free(input[i]);
	return 0;
}
