#ifndef SHA_KERNEL_H_
#define SHA_KERNEL_H_

#include <stdint.h>

#define SHA256_DIGEST_SIZE 32
#define MAX_CHUNK_SIZE     8192
#define SHA256_BLOCK_SIZE  64
#define MAX_CHUNK_WORDS    (MAX_CHUNK_SIZE / 4)   // input is read as 32-bit words

// ---------------------------------------------------------------- batching
// One kernel call hashes up to SHA_BATCH_MAX_CHUNKS chunks. Input buffer layout (32-bit words):
//   words [0, SHA_BATCH_MAX_CHUNKS)       : chunk lengths in bytes (only the first num_chunks are used)
//   words [SHA_BATCH_HDR_WORDS, ...)      : chunk data, back to back; each chunk starts on a 4-byte
//                                           boundary, i.e. chunk i+1 starts ceil(len_i / 4) words after chunk i
// Output buffer: 8 words (32 bytes, standard big-endian digest byte order) per chunk, in chunk order.
#define SHA_BATCH_MAX_CHUNKS 32
#define SHA_BATCH_HDR_WORDS  SHA_BATCH_MAX_CHUNKS
#define SHA_BATCH_IN_WORDS   (SHA_BATCH_HDR_WORDS + SHA_BATCH_MAX_CHUNKS * MAX_CHUNK_WORDS)
#define SHA_BATCH_IN_BYTES   (SHA_BATCH_IN_WORDS * 4)                       // 262,272 bytes
#define SHA_BATCH_OUT_WORDS  (SHA_BATCH_MAX_CHUNKS * (SHA256_DIGEST_SIZE / 4))
#define SHA_BATCH_OUT_BYTES  (SHA_BATCH_OUT_WORDS * 4)                      // 1,024 bytes

extern "C" {
// input_data    : batch buffer laid out as above (lengths, then word-aligned chunk data)
// output_digest : 8 words per chunk, chunk i at output_digest[8*i]
// num_chunks    : number of chunks in this batch, 1..SHA_BATCH_MAX_CHUNKS
void sha256_kernel(const uint32_t* input_data, uint32_t* output_digest, uint32_t num_chunks);
}

#endif // SHA_KERNEL_H_
