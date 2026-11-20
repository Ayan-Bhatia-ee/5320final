#include "sha_kernel.h"
#include <string.h>


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

static inline uint32_t bswap32(uint32_t x) {
	#pragma HLS INLINE
	return ((x & 0x000000FFu) << 24) |
	       ((x & 0x0000FF00u) << 8)  |
	       ((x & 0x00FF0000u) >> 8)  |
	       ((x & 0xFF000000u) >> 24);
}

static void sha256_kernel_block(uint32_t h[8], const uint32_t block_words[16]) {
	#pragma HLS INLINE off
	uint32_t w[16];
	#pragma HLS ARRAY_PARTITION variable=w complete dim=1

	uint32_t a = h[0], b = h[1], c = h[2], d = h[3];
	uint32_t e = h[4], f = h[5], g = h[6], hh = h[7];

	for (int t = 0; t < 64; t++) {
		#pragma HLS PIPELINE II=1
		uint32_t wt;
		if (t < 16) {
			wt = block_words[t];
		} else {
			uint32_t s0 = ROR32(w[1], 7) ^ ROR32(w[1], 18) ^ (w[1] >> 3);
			uint32_t s1 = ROR32(w[14], 17) ^ ROR32(w[14], 19) ^ (w[14] >> 10);
			wt = w[0] + s0 + w[9] + s1;
		}

		for (int i = 0; i < 15; i++) {
			#pragma HLS UNROLL
			w[i] = w[i + 1];
		}
		w[15] = wt;

		uint32_t S1 = ROR32(e, 6) ^ ROR32(e, 11) ^ ROR32(e, 25);
		uint32_t ch = (e & f) ^ (~e & g);
		uint32_t t1 = hh + S1 + ch + K256[t] + wt;
		uint32_t S0 = ROR32(a, 2) ^ ROR32(a, 13) ^ ROR32(a, 22);
		uint32_t maj = (a & b) ^ (a & c) ^ (b & c);
		uint32_t t2 = S0 + maj;

		hh = g; g = f; f = e; e = d + t1;
		d = c; c = b; b = a; a = t1 + t2;
	}

	h[0] += a; h[1] += b; h[2] += c; h[3] += d;
	h[4] += e; h[5] += f; h[6] += g; h[7] += hh;
}

void sha256_kernel(const uint32_t* input_data, uint32_t* output_digest, uint32_t length) {
	#pragma HLS INTERFACE m_axi port=input_data    offset=slave bundle=gmem0 depth=2048
	#pragma HLS INTERFACE m_axi port=output_digest offset=slave bundle=gmem1 depth=8

	#pragma HLS INTERFACE s_axilite port=input_data    bundle=control
	#pragma HLS INTERFACE s_axilite port=output_digest bundle=control
	#pragma HLS INTERFACE s_axilite port=length        bundle=control
	#pragma HLS INTERFACE s_axilite port=return        bundle=control

	uint32_t h[8] = {0x6a09e667,0xbb67ae85,0x3c6ef372,0xa54ff53a,
	                 0x510e527f,0x9b05688c,0x1f83d9ab,0x5be0cd19};
	#pragma HLS ARRAY_PARTITION variable=h complete dim=1

	// 32 words headroom ensures 8192-byte chunks can append the 129th padding block safely
	uint32_t local_words[(MAX_CHUNK_SIZE / 4) + 32];

	// Burst-read 32-bit words from DRAM (4 bytes/cycle)
	uint32_t num_in_words = (length + 3) >> 2;
	for (uint32_t i = 0; i < num_in_words; i++) {
		#pragma HLS PIPELINE II=1
		local_words[i] = bswap32(input_data[i]);
	}

	// Mask out unaligned trailing bytes and append SHA-256 0x80 + bit-length padding
	uint32_t last_word_idx = length >> 2;
	uint32_t byte_rem      = length & 3;
	uint32_t keep_mask     = (byte_rem == 0) ? 0u : (~0u << ((4 - byte_rem) * 8));
	uint32_t pad_marker    = 0x80u << ((3 - byte_rem) * 8);
	uint32_t raw_last      = (byte_rem == 0) ? 0u : local_words[last_word_idx];
	local_words[last_word_idx] = (raw_last & keep_mask) | pad_marker;

	uint32_t total_blocks = (length + 9 + 63) >> 6;
	uint32_t total_words  = total_blocks << 4;
	uint32_t len_word_idx = total_words - 2;

	for (uint32_t i = last_word_idx + 1; i < len_word_idx; i++) {
		#pragma HLS PIPELINE II=1
		local_words[i] = 0;
	}

	uint64_t bit_len = (uint64_t) length * 8;
	local_words[len_word_idx]     = (uint32_t)(bit_len >> 32);
	local_words[len_word_idx + 1] = (uint32_t)(bit_len & 0xFFFFFFFFu);

	// Process all 16-word (64-byte) blocks
	for (uint32_t b = 0; b < total_blocks; b++) {
		sha256_kernel_block(h, local_words + (b << 4));
	}

	// 4. Write 256-bit digest back in 8 beats
	for (int i = 0; i < 8; i++) {
		#pragma HLS UNROLL
		output_digest[i] = bswap32(h[i]);
	}
}
