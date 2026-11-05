// ESE5320 Project Part 1 - placeholder encoder (single ARM core)
//
// Pipeline (all in one thread for now):
//   packets -> CDC -> hash -> dedup lookup -> (LZW | duplicate header) -> output buffer
//
// Interfaces between components:
//   CDC     : push bytes in, calls back once per finished chunk with
//             (const uint8_t* data, uint32_t len)   [data lives in CDC's 8 KiB buffer]
//   Hash    : (data, len)            -> uint64_t digest        (placeholder: FNV-1a)
//   Dedup   : (digest, data, len)    -> chunk index or -1      (verifies bytes on a hash hit)
//   LZW     : (data, len, out)       -> appends 32b header + packed 13b codes
//   Output  : growing byte vector in DRAM, written to a file at the end
//
// Placeholders:
//   CDC   - simple polynomial rolling hash, 16B window, min 2 KiB / max 8 KiB
//   Hash  - 64-bit FNV-1a instead of SHA (so hits are verified with memcmp)
//   LZW   - no dictionary: every input byte is sent as its literal code (0-255)
//           in a 13-bit field. Valid for the provided decoder, but expands data by 13/8.

#include "encoder.h"

#include <stdio.h>
#include <stdint.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <iostream>
#include <vector>
#include <unordered_map>
#include "server.h"
#include "stopwatch.h"

// max payload per packet is 16 KiB; normally defined in encoder.h
#ifndef NUM_ELEMENTS
#define NUM_ELEMENTS 16384
#endif

#define NUM_PACKETS 8
#define pipe_depth 4
#define DONE_BIT_L (1 << 7)
#define DONE_BIT_H (1 << 15)

#define CODE_LENGTH 13          // must match decoder (ceil(log2(8192)))
#define MAX_CHUNK   8192
#define MIN_CHUNK   2048
#define CDC_WINDOW  16
#define CDC_MASK    0x7FF       // ~2 KiB expected past MIN_CHUNK => ~4 KiB average
#define CDC_PRIME   31u

typedef std::vector<uint8_t> bytes;

// ---------------------------------------------------------------- output
static bytes Output;

static void put_u32(uint32_t v) {          // headers are little endian (matches decoder)
	for (int i = 0; i < 4; i++) Output.push_back((v >> (8 * i)) & 0xFF);
}

// ---------------------------------------------------------------- hash (placeholder for SHA)
static uint64_t hash_chunk(const uint8_t* d, uint32_t len) {
	uint64_t h = 1469598103934665603ULL;
	for (uint32_t i = 0; i < len; i++) {
		h ^= d[i];
		h *= 1099511628211ULL;
	}
	return h;
}

// ---------------------------------------------------------------- dedup
static std::unordered_multimap<uint64_t, uint32_t> Hash_to_index;
static std::vector<bytes> Unique_chunks;    // raw copies, used to verify a hash hit

// returns index of earlier identical LZW chunk, or -1
static int64_t dedup_lookup(uint64_t h, const uint8_t* d, uint32_t len) {
	auto range = Hash_to_index.equal_range(h);
	for (auto it = range.first; it != range.second; ++it) {
		const bytes& c = Unique_chunks[it->second];
		if (c.size() == len && memcmp(c.data(), d, len) == 0)
			return it->second;
	}
	return -1;
}

static void dedup_insert(uint64_t h, const uint8_t* d, uint32_t len) {
	uint32_t idx = Unique_chunks.size();
	Unique_chunks.push_back(bytes(d, d + len));
	Hash_to_index.insert({h, idx});
}

// ---------------------------------------------------------------- LZW (placeholder)
static void lzw_encode(const uint8_t* d, uint32_t len) {
	uint32_t comp_bytes = (len * CODE_LENGTH + 7) / 8;
	put_u32(comp_bytes << 1);                // bit0 = 0 -> LZW chunk

	// MSB-first bit packing
	uint32_t acc = 0;
	int nbits = 0;
	for (uint32_t i = 0; i < len; i++) {
		acc = (acc << CODE_LENGTH) | d[i];   // literal code == byte value
		nbits += CODE_LENGTH;
		while (nbits >= 8) {
			Output.push_back((acc >> (nbits - 8)) & 0xFF);
			nbits -= 8;
		}
		acc &= (1u << nbits) - 1;            // keep only the leftover bits
	}
	if (nbits > 0)                           // pad to byte boundary
		Output.push_back((acc << (8 - nbits)) & 0xFF);
}

// ---------------------------------------------------------------- per-chunk path
static uint64_t Total_chunks = 0, Dup_chunks = 0;

static void process_chunk(const uint8_t* d, uint32_t len) {
	Total_chunks++;
	uint64_t h = hash_chunk(d, len);
	int64_t idx = dedup_lookup(h, d, len);
	if (idx >= 0) {
		Dup_chunks++;
		put_u32(((uint32_t) idx << 1) | 1);  // bit0 = 1 -> duplicate chunk
	} else {
		dedup_insert(h, d, len);
		lzw_encode(d, len);
	}
}

// ---------------------------------------------------------------- CDC (placeholder)
// Streaming: state persists across packets so chunks may span packet boundaries.
static uint8_t  Chunk_buf[MAX_CHUNK];
static uint32_t Chunk_len = 0;
static uint32_t Roll = 0;
static uint32_t Prime_pow_w = 1;             // CDC_PRIME^CDC_WINDOW

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
		if (Chunk_len >= CDC_WINDOW)         // remove byte leaving the window
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

// ---------------------------------------------------------------- main / input
void handle_input(int argc, char* argv[], int* blocksize, const char** outname) {
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
	if (optind < argc) *outname = argv[optind];   // final spec: one arg = output file
}

int main(int argc, char* argv[]) {
	stopwatch ethernet_timer;
	stopwatch total_timer;
	unsigned char* input[NUM_PACKETS];
	int writer = 0;
	int done = 0;
	int length = 0;
	uint64_t bytes_in = 0;
	ESE532_Server server;

	int blocksize = BLOCKSIZE;
	const char* outname = "output_cpu.bin";
	handle_input(argc, argv, &blocksize, &outname);

	for (int i = 0; i < NUM_PACKETS; i++) {
		input[i] = (unsigned char*) malloc(sizeof(unsigned char) * (NUM_ELEMENTS + HEADER));
		if (input[i] == NULL) {
			std::cout << "aborting " << std::endl;
			return 1;
		}
	}

	Output.reserve(1 << 26);
	cdc_init();
	server.setup_server(blocksize);

	writer = 0;
	total_timer.start();
	while (!done) {
		ethernet_timer.start();
		server.get_packet(input[writer]);
		ethernet_timer.stop();

		unsigned char* buffer = input[writer];
		done = buffer[1] & DONE_BIT_L;
		length = buffer[0] | (buffer[1] << 8);
		length &= ~DONE_BIT_H;

		cdc_push(&buffer[HEADER], length);   // CDC -> hash -> dedup -> LZW
		bytes_in += length;

		writer = (writer + 1) % NUM_PACKETS;
	}
	cdc_flush();                             // last (possibly short) chunk
	total_timer.stop();

	FILE *outfd = fopen(outname, "wb");
	if (outfd == NULL) { printf("cannot open %s\n", outname); return 1; }
	size_t bytes_written = fwrite(Output.data(), 1, Output.size(), outfd);
	printf("wrote %zu compressed bytes (%llu input bytes)\n", bytes_written,
	       (unsigned long long) bytes_in);
	fclose(outfd);

	printf("chunks: %llu total, %llu duplicates\n",
	       (unsigned long long) Total_chunks, (unsigned long long) Dup_chunks);

	for (int i = 0; i < NUM_PACKETS; i++) free(input[i]);

	std::cout << "--------------- Key Throughputs ---------------" << std::endl;
	float ethernet_latency = ethernet_timer.latency() / 1000.0;
	float input_throughput = (bytes_in * 8 / 1000000.0) / ethernet_latency; // Mb/s
	std::cout << "Input Throughput to Encoder: " << input_throughput << " Mb/s."
			<< " (Latency: " << ethernet_latency << "s)." << std::endl;
	return 0;
}