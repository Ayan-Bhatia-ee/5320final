// ESE5320 Project - functional single-core encoder (Part 2 milestone)
//
// Flow:  Ethernet packets -> CDC -> SHA-256 -> dedup lookup -+-> duplicate header
//                                                            +-> LZW -> output buffer -> file
//
// Components (all plain C-style functions on fixed-size arrays, so they are
// easy to lift into HLS later):
//   cdc_push()   : streaming content-defined chunking, rolling hash, 2-8 KiB chunks (~4 KiB avg)
//   sha256()     : serialized software SHA-256 (SHA option 1)
//   dedup_*()    : digest -> chunk index map; equal SHA-256 == duplicate (per handout, no byte check)
//   lzw_encode() : real LZW, 13-bit codes, MSB-first, dictionary reset per chunk
//
// Sources: SHA-256 follows FIPS 180-4; LZW follows the standard algorithm in the project
// handout, adapted to the provided decoder (13-bit fixed codes, no end code).
// test

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

// ---------------------------------------------------------------- output buffer
static bytes Output;

static void put_u32(uint32_t v) {       // headers are little endian (matches decoder on ARM/x86)
	for (int i = 0; i < 4; i++) Output.push_back((v >> (8 * i)) & 0xFF);
}

// ================================================================ SHA-256 (FIPS 180-4)
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
	sha256(d, len, dg.b);
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
	if (optind < argc) *outname = argv[optind];   // one argument: compressed output file
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

	total_timer.start();
	while (!done) {
		ethernet_timer.start();
		server.get_packet(input[writer]);
		ethernet_timer.stop();

		unsigned char* buffer = input[writer];
		done = buffer[1] & DONE_BIT_L;
		length = buffer[0] | (buffer[1] << 8);
		length &= ~DONE_BIT_H;

		Push_timer.start();
		cdc_push(&buffer[HEADER], length);    // CDC -> SHA -> dedup -> LZW
		Push_timer.stop();
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
	fclose(outfd);

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

	std::cout << "--------------- Key Throughputs ---------------" << std::endl;
	float ethernet_latency = ethernet_timer.latency() / 1000.0;
	float input_throughput = (bytes_in * 8 / 1000000.0) / ethernet_latency; // Mb/s
	std::cout << "Input Throughput to Encoder: " << input_throughput << " Mb/s."
			<< " (Latency: " << ethernet_latency << "s)." << std::endl;
	if (compute_ms > 0)
		std::cout << "Compute-only throughput    : "
				<< (bytes_in * 8 / 1000000.0) / (compute_ms / 1000.0) << " Mb/s." << std::endl;

	for (int i = 0; i < NUM_PACKETS; i++) free(input[i]);
	return 0;
}
