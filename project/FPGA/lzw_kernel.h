#ifndef LZW_KERNEL_H
#define LZW_KERNEL_H

#include <stdint.h>

enum {
    LZW_CODE_BITS = 13,
    LZW_MAX_INPUT = 8192,
    LZW_MAX_PAYLOAD = (LZW_MAX_INPUT * LZW_CODE_BITS + 7) / 8,
    LZW_MAX_OUTPUT = 4 + LZW_MAX_PAYLOAD
};

extern "C" void lzw_kernel(const uint8_t* input, uint8_t* output,
                           uint32_t length);

#endif
