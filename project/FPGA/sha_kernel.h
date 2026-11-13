#ifndef SHA_KERNEL_H_
#define SHA_KERNEL_H_

#include <stdint.h>

#define SHA256_DIGEST_SIZE 32
#define MAX_CHUNK_SIZE     8192
#define SHA256_BLOCK_SIZE  64
#define MAX_CHUNK_WORDS    (MAX_CHUNK_SIZE / 8)   // input is read as 64-bit words

extern "C" {
// input_data    : chunk bytes, read 8 at a time (host buffer is MAX_CHUNK_SIZE bytes)
// output_digest : 32-byte SHA-256 digest, standard big-endian byte order
// length        : chunk length in bytes, <= MAX_CHUNK_SIZE
void sha256_kernel(const uint64_t* input_data, uint8_t* output_digest, uint32_t length);
}

#endif // SHA_KERNEL_H_
