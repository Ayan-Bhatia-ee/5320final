#include "lzw_kernel.h"

// At most seven bits remain from the previous code, so a 32-bit accumulator
// holds the next 13-bit code and produces at most two complete bytes.
static void emit_code(uint32_t code, uint8_t* output, uint32_t& pos,
                      uint32_t& bits, unsigned& count) {
    bits = (bits << LZW_CODE_BITS) | code;
    count += LZW_CODE_BITS;
    for (int byte = 0; byte < 2 && count >= 8; ++byte) {
        count -= 8;
        output[pos++] = static_cast<uint8_t>(bits >> count);
    }
}

extern "C" void lzw_kernel(const uint8_t* input, uint8_t* output,
                           uint32_t length) {
#pragma HLS INTERFACE m_axi port=input         offset=slave bundle=gmem0 depth=8192
#pragma HLS INTERFACE m_axi port=output        offset=slave bundle=gmem1 depth=13316
#pragma HLS INTERFACE s_axilite port=input         bundle=control
#pragma HLS INTERFACE s_axilite port=output        bundle=control
#pragma HLS INTERFACE s_axilite port=length        bundle=control
#pragma HLS INTERFACE s_axilite port=return        bundle=control
// Match fpga_example/MMult (the design that worked on this board): plain start/done
// handshake instead of the Vitis default ap_ctrl_chain, which both failing kernels used.
#pragma HLS INTERFACE ap_ctrl_hs port=return

    if (length == 0 || length > LZW_MAX_INPUT) {
        output[0] = output[1] = output[2] = output[3] = 0;
        return;
    }

    // Match the successful fpga_example's load/compute/store structure: build
    // the variable-size result in BRAM, then issue one sequential AXI write loop.
    uint8_t local_output[LZW_MAX_OUTPUT];
#pragma HLS BIND_STORAGE variable=local_output type=ram_1p impl=bram

    // Load stage (like fpga_example's load): copy the chunk into BRAM with one
    // pipelined sequential loop so the compute loop below never touches DDR.
    uint8_t local_input[LZW_MAX_INPUT];
#pragma HLS BIND_STORAGE variable=local_input type=ram_1p impl=bram

load_input:
    for (uint32_t i = 0; i < length; ++i) {
#pragma HLS PIPELINE II=1
#pragma HLS LOOP_TRIPCOUNT min=1 max=8192
        local_input[i] = input[i];
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
    uint32_t prefix = local_input[0];
    uint32_t pos = 4, bits = 0; // reserve the final stream's four-byte chunk header
    unsigned count = 0;
    for (uint32_t i = 1; i < length; ++i) {
        uint8_t c = local_input[i];
        uint32_t key = (prefix << 8) | c;
        uint32_t slot = (key * 2654435761u) >> (32 - table_bits);
        // Only 7,936 phrases fit in 13-bit codes. A miss always reaches
        // an empty slot before this bounded probe wraps around the table.
        for (unsigned p = 0; p < slots; ++p) {
            if (!valid[slot]) {
                emit_code(prefix, local_output, pos, bits, count);
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

    emit_code(prefix, local_output, pos, bits, count);
    if (count != 0) local_output[pos++] = static_cast<uint8_t>(bits << (8 - count));

    // Same little-endian record header consumed by Decoder.cpp:
    // bit 0 = 0 for an LZW record; bits 31:1 = payload size in bytes.
    uint32_t header = (pos - 4) << 1;
    local_output[0] = static_cast<uint8_t>(header);
    local_output[1] = static_cast<uint8_t>(header >> 8);
    local_output[2] = static_cast<uint8_t>(header >> 16);
    local_output[3] = static_cast<uint8_t>(header >> 24);

store_output:
    for (uint32_t i = 0; i < pos; ++i) {
#pragma HLS PIPELINE II=1
#pragma HLS LOOP_TRIPCOUNT min=6 max=13316
        output[i] = local_output[i];
    }
}
