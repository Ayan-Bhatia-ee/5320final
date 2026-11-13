// ESE5320 Project - encoder host code, SHA-256 on the FPGA (FPGA milestone, baseline)
//
// Flow:  Ethernet packets -> CDC (ARM) -> SHA-256 (FPGA kernel, OpenCL) -> dedup (ARM)
//                                                 -+-> duplicate header
//                                                  +-> LZW (ARM) -> output buffer -> file
//
// Baseline version: one kernel call per chunk (copy in, run, copy out, wait).
// Kernel: sha_kernel.cpp (sha256_kernel). Build: see Makefile / u96_v2.cfg.
// Usage:  ./encoder [-b blocksize] <compressed output file> [xclbin]   (xclbin defaults to encoder.xclbin)

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
#define MAX_CHUNK   8192
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
	Fpga->in_ptr  = (uint8_t*) Fpga->q.enqueueMapBuffer(Fpga->in_buf,  CL_TRUE, CL_MAP_WRITE, 0, MAX_CHUNK_SIZE);
	Fpga->out_ptr = (uint8_t*) Fpga->q.enqueueMapBuffer(Fpga->out_buf, CL_TRUE, CL_MAP_READ,  0, SHA256_DIGEST_SIZE);

	// kernel arguments: 0 = input_data, 1 = output_digest, 2 = length (set per chunk)
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

// Hash one chunk (len <= MAX_CHUNK_SIZE) on the FPGA.
static void sha256_fpga(const uint8_t* d, uint32_t len, uint8_t out[32]) {
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

	total_timer.start();
	while (!done) {
		ethernet_timer.start();
		server.get_packet(input[writer]);
		ethernet_timer.stop();

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

	std::cout << "--------------- Key Throughputs ---------------" << std::endl;
	float ethernet_latency = ethernet_timer.latency() / 1000.0;
	float input_throughput = (bytes_in * 8 / 1000000.0) / ethernet_latency; // Mb/s
	std::cout << "Input Throughput to Encoder: " << input_throughput << " Mb/s."
			<< " (Latency: " << ethernet_latency << "s)." << std::endl;
	if (compute_ms > 0)
		std::cout << "Compute-only throughput    : "
				<< (bytes_in * 8 / 1000000.0) / (compute_ms / 1000.0) << " Mb/s." << std::endl;

	opencl_shutdown();
	for (int i = 0; i < NUM_PACKETS; i++) free(input[i]);
	return 0;
}