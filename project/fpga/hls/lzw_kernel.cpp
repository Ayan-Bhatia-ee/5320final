#include "lzw_kernel.h"

// At most seven bits remain from the previous code, so a 32-bit accumulator
// holds the next 13-bit code and produces at most two complete bytes.
static void emit_code(uint32_t code, uint8_t* payload, uint32_t& pos,
                      uint32_t& bits, unsigned& count) {
    bits = (bits << LZW_CODE_BITS) | code;
    count += LZW_CODE_BITS;
    for (int byte = 0; byte < 2 && count >= 8; ++byte) {
        count -= 8;
        payload[pos++] = static_cast<uint8_t>(bits >> count);
    }
}

extern "C" void lzw_kernel(const uint8_t* input, uint8_t* payload,
                           uint32_t* payload_bytes, uint32_t length) {
#pragma HLS INTERFACE m_axi port=input         offset=slave bundle=gmem depth=8192
#pragma HLS INTERFACE m_axi port=payload       offset=slave bundle=gmem depth=13312
#pragma HLS INTERFACE m_axi port=payload_bytes offset=slave bundle=gmem depth=1
#pragma HLS INTERFACE s_axilite port=input         bundle=control
#pragma HLS INTERFACE s_axilite port=payload       bundle=control
#pragma HLS INTERFACE s_axilite port=payload_bytes bundle=control
#pragma HLS INTERFACE s_axilite port=length        bundle=control
#pragma HLS INTERFACE s_axilite port=return        bundle=control

    if (length == 0 || length > LZW_MAX_INPUT) {
        *payload_bytes = 0;
        return;
    }

    const unsigned table_bits = 14;
    const unsigned slots = 1u << table_bits;
    uint32_t keys[slots];
    uint16_t codes[slots];
    bool valid[slots];
#pragma HLS BIND_STORAGE variable=keys  type=ram_1p impl=bram
#pragma HLS BIND_STORAGE variable=codes type=ram_1p impl=bram
#pragma HLS BIND_STORAGE variable=valid type=ram_1p impl=bram

    for (unsigned i = 0; i < slots; ++i) {
#pragma HLS PIPELINE II=1
        valid[i] = false;
    }

    uint32_t next_code = 256;
    uint32_t prefix = input[0];
    uint32_t pos = 0, bits = 0;
    unsigned count = 0;
    for (uint32_t i = 1; i < length; ++i) {
        uint8_t c = input[i];
        uint32_t key = (prefix << 8) | c;
        uint32_t slot = (key * 2654435761u) >> (32 - table_bits);
        // Only 7,936 phrases fit in 13-bit codes. A miss always reaches
        // an empty slot before this bounded probe wraps around the table.
        for (unsigned p = 0; p < slots; ++p) {
            if (!valid[slot]) {
                emit_code(prefix, payload, pos, bits, count);
                if (next_code < (1u << LZW_CODE_BITS)) {
                    keys[slot] = key;
                    codes[slot] = next_code++;
                    valid[slot] = true;
                }
                prefix = c;
                break;
            }
            if (keys[slot] == key) {
                prefix = codes[slot];
                break;
            }
            slot = (slot + 1) & (slots - 1);
        }
    }

    emit_code(prefix, payload, pos, bits, count);
    if (count != 0) payload[pos++] = static_cast<uint8_t>(bits << (8 - count));
    *payload_bytes = pos;
}
