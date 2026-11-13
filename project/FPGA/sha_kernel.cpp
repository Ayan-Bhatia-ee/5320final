// SHA-256 kernel (FIPS 180-4), one chunk per call.
//
// Same OpenCL interface as before (input_data, output_digest, length; bundles gmem0/gmem1),
// so u96_v2.cfg and the host's setArg calls do not change. Internally:
//
//   load  : burst-reads the chunk as 64-bit words (8 bytes/cycle instead of 1)
//   hash  : builds each 64-byte block on the fly, including padding, and runs the
//           64 rounds pipelined at II=1, message schedule as a 16-word shift register
//   store : writes the 32-byte digest
//
// load / hash / store form a DATAFLOW pipeline, so reading the chunk overlaps hashing it.
// No local copy of the chunk is kept.

#include "sha_kernel.h"
#include <hls_stream.h>

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

static uint32_t clamp_len(uint32_t length) {
	return (length > MAX_CHUNK_SIZE) ? MAX_CHUNK_SIZE : length;   // never read past the buffer
}

// ---------------------------------------------------------------- stage 1: DDR -> stream
static void load(const uint64_t* in, uint32_t length, hls::stream<uint64_t>& data_s) {
	uint32_t words = (clamp_len(length) + 7) / 8;
	for (uint32_t w = 0; w < words; w++) {          // sequential -> AXI burst
#pragma HLS PIPELINE II=1
#pragma HLS LOOP_TRIPCOUNT min=256 max=1024 avg=384
		data_s.write(in[w]);
	}
}

// ---------------------------------------------------------------- one 512-bit block
// W is a 16-word shift register: W[0] is w[t], and w[t+16] is computed from fixed
// positions (w[t+14], w[t+9], w[t+1], w[t]), so there is no variable indexing.
static void compress(uint32_t h[8], const uint32_t m[16]) {
#pragma HLS INLINE
	uint32_t W[16];
#pragma HLS ARRAY_PARTITION variable=W complete dim=1
	for (int t = 0; t < 16; t++) {
#pragma HLS UNROLL
		W[t] = m[t];
	}

	uint32_t a = h[0], b = h[1], c = h[2], d = h[3];
	uint32_t e = h[4], f = h[5], g = h[6], hh = h[7];

	for (int t = 0; t < 64; t++) {
#pragma HLS PIPELINE II=1
		uint32_t wt = W[0];

		uint32_t s0 = ROR32(W[1], 7) ^ ROR32(W[1], 18) ^ (W[1] >> 3);
		uint32_t s1 = ROR32(W[14], 17) ^ ROR32(W[14], 19) ^ (W[14] >> 10);
		uint32_t wn = W[0] + s0 + W[9] + s1;
		for (int k = 0; k < 15; k++) {
#pragma HLS UNROLL
			W[k] = W[k + 1];
		}
		W[15] = wn;

		uint32_t S1  = ROR32(e, 6) ^ ROR32(e, 11) ^ ROR32(e, 25);
		uint32_t ch  = (e & f) ^ (~e & g);
		uint32_t t1  = hh + S1 + ch + K256[t] + wt;
		uint32_t S0  = ROR32(a, 2) ^ ROR32(a, 13) ^ ROR32(a, 22);
		uint32_t maj = (a & b) ^ (a & c) ^ (b & c);
		uint32_t t2  = S0 + maj;
		hh = g; g = f; f = e; e = d + t1;
		d = c; c = b; b = a; a = t1 + t2;
	}

	h[0] += a; h[1] += b; h[2] += c; h[3] += d;
	h[4] += e; h[5] += f; h[6] += g; h[7] += hh;
}

// ---------------------------------------------------------------- stage 2: pad + hash
// Every byte position of every block is generated the same way, so there are no
// special cases for the 56..63-byte remainder:
//   pos <  len          -> data byte
//   pos == len          -> 0x80
//   pos >  len          -> 0
//   last block, 56..63  -> 64-bit big-endian bit length
static void hash(uint32_t length, hls::stream<uint64_t>& data_s, hls::stream<uint32_t>& dig_s) {
	uint32_t len     = clamp_len(length);
	uint32_t words   = (len + 7) / 8;              // words the loader sends
	uint32_t nblocks = (len + 8) / 64 + 1;         // room for data + 0x80 + 8-byte length
	uint32_t taken   = 0;

	uint32_t h[8] = {0x6a09e667, 0xbb67ae85, 0x3c6ef372, 0xa54ff53a,
	                 0x510e527f, 0x9b05688c, 0x1f83d9ab, 0x5be0cd19};
#pragma HLS ARRAY_PARTITION variable=h complete dim=1

	for (uint32_t blk = 0; blk < nblocks; blk++) {
#pragma HLS LOOP_TRIPCOUNT min=33 max=129 avg=65
		uint32_t m[16];
#pragma HLS ARRAY_PARTITION variable=m complete dim=1

		for (int j = 0; j < 8; j++) {              // 8 x 64-bit words = one 64-byte block
#pragma HLS PIPELINE II=1
			uint64_t v = 0;
			if (taken < words) v = data_s.read();
			taken++;

			uint32_t base = blk * 64 + j * 8;
			uint8_t by[8];
#pragma HLS ARRAY_PARTITION variable=by complete dim=1
			for (int k = 0; k < 8; k++) {          // ARM is little-endian: byte k = bits 8k+7..8k
#pragma HLS UNROLL
				uint32_t pos = base + k;
				uint8_t  dat = (v >> (8 * k)) & 0xFF;
				by[k] = (pos < len) ? dat : (pos == len ? (uint8_t) 0x80 : (uint8_t) 0);
			}
			m[2 * j]     = ((uint32_t) by[0] << 24) | ((uint32_t) by[1] << 16) |
			               ((uint32_t) by[2] << 8)  |  (uint32_t) by[3];
			m[2 * j + 1] = ((uint32_t) by[4] << 24) | ((uint32_t) by[5] << 16) |
			               ((uint32_t) by[6] << 8)  |  (uint32_t) by[7];
		}

		if (blk == nblocks - 1) {
			uint64_t bits = (uint64_t) len * 8;
			m[14] = (uint32_t) (bits >> 32);
			m[15] = (uint32_t) bits;
		}
		compress(h, m);
	}

	for (int k = 0; k < 8; k++) {
#pragma HLS PIPELINE II=1
		dig_s.write(h[k]);
	}
}

// ---------------------------------------------------------------- stage 3: stream -> DDR
static void store(hls::stream<uint32_t>& dig_s, uint8_t* out) {
	for (int k = 0; k < 8; k++) {
#pragma HLS PIPELINE II=4
		uint32_t v = dig_s.read();
		out[4 * k]     = v >> 24;
		out[4 * k + 1] = v >> 16;
		out[4 * k + 2] = v >> 8;
		out[4 * k + 3] = v;
	}
}

extern "C" {
void sha256_kernel(const uint64_t* input_data, uint8_t* output_digest, uint32_t length) {
#pragma HLS INTERFACE m_axi port=input_data    offset=slave bundle=gmem0 depth=1024 max_read_burst_length=64
#pragma HLS INTERFACE m_axi port=output_digest offset=slave bundle=gmem1 depth=32
#pragma HLS INTERFACE s_axilite port=input_data    bundle=control
#pragma HLS INTERFACE s_axilite port=output_digest bundle=control
#pragma HLS INTERFACE s_axilite port=length        bundle=control
#pragma HLS INTERFACE s_axilite port=return        bundle=control

#pragma HLS DATAFLOW
	hls::stream<uint64_t> data_s("data_s");
	hls::stream<uint32_t> dig_s("dig_s");
#pragma HLS STREAM variable=data_s depth=64
#pragma HLS STREAM variable=dig_s  depth=8

	load(input_data, length, data_s);
	hash(length, data_s, dig_s);
	store(dig_s, output_digest);
}
}
