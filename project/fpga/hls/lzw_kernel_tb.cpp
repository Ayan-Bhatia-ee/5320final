#include "lzw_kernel.h"

#include <algorithm>
#include <cstdio>
#include <fstream>
#include <iterator>
#include <map>
#include <vector>

typedef std::vector<uint8_t> Bytes;

// Independent software oracle: use a map and write bits individually so
// hash collisions and bit-packing errors in the kernel are observable.
static Bytes reference_payload(const Bytes& input) {
    if (input.empty()) return {};
    std::map<uint32_t, uint32_t> dictionary;
    std::vector<uint32_t> codes;
    uint32_t prefix = input.front();
    for (size_t i = 1; i < input.size(); ++i) {
        uint32_t key = (prefix << 8) | input[i];
        auto entry = dictionary.find(key);
        if (entry != dictionary.end()) {
            prefix = entry->second;
        } else {
            codes.push_back(prefix);
            uint32_t next_code = 256 + dictionary.size();
            if (next_code < (1u << LZW_CODE_BITS)) dictionary[key] = next_code;
            prefix = input[i];
        }
    }
    codes.push_back(prefix);
    Bytes output((codes.size() * LZW_CODE_BITS + 7) / 8, 0);
    size_t bit = 0;
    for (uint32_t code : codes) {
        for (int shift = LZW_CODE_BITS - 1; shift >= 0; --shift, ++bit) {
            output[bit / 8] |= ((code >> shift) & 1u) << (7 - bit % 8);
        }
    }
    return output;
}

static bool check_chunk(const char* name, const Bytes& chunk, const Bytes& expected) {
    // C/RTL co-simulation models the full declared AXI depths for every call.
    uint8_t input[LZW_MAX_INPUT] = {};
    uint8_t output[LZW_MAX_PAYLOAD] = {};
    std::copy(chunk.begin(), chunk.end(), input);
    uint32_t count = UINT32_MAX;
    lzw_kernel(input, output, &count, chunk.size());
    if (count != expected.size() || !std::equal(expected.begin(), expected.end(), output)) {
        std::fprintf(stderr, "%s failed (got %u bytes, expected %zu)\n", name, count, expected.size());
        return false;
    }
    return true;
}

int main() {
    if (!check_chunk("empty", {}, {}) || !check_chunk("single A", {'A'}, {0x02, 0x08})) return 1;
    Bytes run(LZW_MAX_INPUT, 'A');
    if (!check_chunk("repeated A", run, reference_payload(run))) return 1;
    run.back() = 'B';
    if (!check_chunk("dictionary reset", run, reference_payload(run))) return 1;

    // Generated once by make for both the native and Vitis simulation runs.
    std::ifstream file("lzw_seed23.bin", std::ios::binary);
    Bytes random{std::istreambuf_iterator<char>(file), std::istreambuf_iterator<char>()};
    if (file.bad() || random.size() != LZW_MAX_INPUT) {
        std::fprintf(stderr, "Expected 8192 bytes in lzw_seed23.bin (run make lzw-test or lzw-cosim)\n");
        return 1;
    }
    Bytes expected = reference_payload(random);
    if (expected.size() != 12584 || !check_chunk("expanding binary", random, expected)) return 1;

    // Disjoint byte ranges and a different adjacent pair at every position
    // force one literal per byte, including after dictionary insertion stops.
    Bytes all_literals;
    for (unsigned i = 0; i < LZW_MAX_INPUT / 2; ++i) {
        all_literals.push_back(i % 128);
        all_literals.push_back(128 + i / 128);
    }
    expected = reference_payload(all_literals);
    if (expected.size() != LZW_MAX_PAYLOAD || !check_chunk("full dictionary", all_literals, expected)) return 1;
    std::puts("LZW kernel payload checks passed");
    return 0;
}
