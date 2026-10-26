// The libFuzzer entry point (clang: -fsanitize=fuzzer,address,undefined). Every target, through one input format.
#include "fuzz_targets.h"

extern "C" int LLVMFuzzerTestOneInput(const uint8_t* data, size_t size) {
    fuzz::run_one(data, size);
    return 0;
}
