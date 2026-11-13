#ifndef SHA_KERNEL_H_
#define SHA_KERNEL_H_

#include <stdint.h>

#define SHA256_DIGEST_SIZE 32 
#define MAX_CHUNK_SIZE     8192 
#define SHA256_BLOCK_SIZE  64   



extern "C" {
    void sha256_kernel(
    const uint8_t* input_data,
    uint8_t* output_digest,
    uint32_t length
);
}



#endif // SHA_KERNEL_H_