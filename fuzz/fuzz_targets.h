#pragma once

#include <cstddef>
#include <cstdint>
#include <string>
#include <vector>

// Fuzzing (M8): every parser that reads data someone else controls. One input format covers them all, so a single
// libFuzzer binary or the built-in driver can exercise everything:
//   input = [target byte][rest]       the target byte picks a target (modulo how many there are)
// and most targets use the first byte of `rest` to pick one of their parsers.
//
// A target must never crash, read out of bounds or hit undefined behaviour on any input (run it under the sanitizers).
// Where a format is canonical, an input that parses must also re-encode to exactly the same bytes: a parser that
// accepts something its own encoder would never write is a bug waiting to happen. A violation calls abort().
namespace fuzz {

using Bytes = std::vector<uint8_t>;

struct Target {
    std::string name;
    // Runs one input; true if the input was accepted by the parser it reached (used to check that the seeds are valid).
    bool (*run)(const uint8_t* data, size_t size);
    // Valid inputs to start mutating from, built with the real encoders.
    std::vector<Bytes> (*seeds)();
};

const std::vector<Target>& targets();

// The entry point shared by libFuzzer and the driver: dispatches on the first byte.
void run_one(const uint8_t* data, size_t size);

}  // namespace fuzz
