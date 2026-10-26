// pq-fuzz: a simple mutation fuzzer for when libFuzzer isn't available (any compiler). Build it with the sanitizers on.
//   pq-fuzz [--seconds N] [--target NAME] [--crash-file PATH]   mutates every target's seeds for N seconds (default 60)
//   pq-fuzz FILE...                                              replays saved inputs (e.g. a crash file)
// If an input makes it crash, or breaks a round trip, that input is written to the crash file before the program dies.
#include <chrono>
#include <csignal>
#include <cstdio>
#include <cstring>
#include <fstream>
#include <iostream>
#include <iterator>
#include <string>
#include <vector>

#include <fcntl.h>
#include <unistd.h>

#include "fuzz_targets.h"

namespace {

std::vector<uint8_t> g_current;
std::string g_crash_file = "pq-fuzz-crash.bin";

void save_current() {
    int fd = ::open(g_crash_file.c_str(), O_WRONLY | O_CREAT | O_TRUNC, 0600);
    if (fd < 0) return;
    if (!g_current.empty()) { auto n = ::write(fd, g_current.data(), g_current.size()); (void)n; }
    ::close(fd);
}

extern "C" void on_abort(int) {
    save_current();
    std::signal(SIGABRT, SIG_DFL);
    std::raise(SIGABRT);
}

struct Rng {
    uint64_t s = 0x9E3779B97F4A7C15ull;
    uint64_t next() { s ^= s << 13; s ^= s >> 7; s ^= s << 17; return s; }
    size_t below(size_t n) { return n ? static_cast<size_t>(next() % n) : 0; }
};

// One to four changes of the kinds that tend to break parsers.
void mutate(std::vector<uint8_t>& b, Rng& r) {
    const int count = 1 + static_cast<int>(r.below(4));
    for (int i = 0; i < count; i++) {
        switch (r.below(8)) {
            case 0: if (!b.empty()) b[r.below(b.size())] ^= static_cast<uint8_t>(1u << r.below(8)); break;
            case 1: if (!b.empty()) b[r.below(b.size())] = static_cast<uint8_t>(r.next()); break;
            case 2: { size_t at = r.below(b.size() + 1); size_t n = 1 + r.below(16); for (size_t k = 0; k < n; k++) b.insert(b.begin() + static_cast<std::ptrdiff_t>(at), static_cast<uint8_t>(r.next())); break; }
            case 3: if (b.size() > 1) { size_t at = r.below(b.size()); size_t n = 1 + r.below(std::min<size_t>(32, b.size() - at)); b.erase(b.begin() + static_cast<std::ptrdiff_t>(at), b.begin() + static_cast<std::ptrdiff_t>(at + n)); } break;
            case 4: if (!b.empty()) b.resize(r.below(b.size())); break;
            case 5: if (b.size() >= 4) {  // a 4-byte length field set to an edge value
                static const uint32_t edges[] = {0, 1, 2, 0x7F, 0x80, 0xFF, 0x100, 0xFFFF, 0x10000, 0x7FFFFFFF, 0x80000000u, 0xFFFFFFFEu, 0xFFFFFFFFu};
                size_t at = r.below(b.size() - 3);
                uint32_t v = edges[r.below(sizeof(edges) / sizeof(edges[0]))];
                if (r.below(2)) v = static_cast<uint32_t>(b.size() - at + r.below(5)) - 2;
                b[at] = static_cast<uint8_t>(v >> 24); b[at + 1] = static_cast<uint8_t>(v >> 16); b[at + 2] = static_cast<uint8_t>(v >> 8); b[at + 3] = static_cast<uint8_t>(v);
            } break;
            case 6: if (b.size() > 2) { size_t at = r.below(b.size()); size_t n = 1 + r.below(std::min<size_t>(64, b.size() - at)); std::vector<uint8_t> chunk(b.begin() + static_cast<std::ptrdiff_t>(at), b.begin() + static_cast<std::ptrdiff_t>(at + n)); b.insert(b.begin() + static_cast<std::ptrdiff_t>(r.below(b.size())), chunk.begin(), chunk.end()); } break;
            default: b.push_back(static_cast<uint8_t>(r.next())); break;
        }
    }
}

}  // namespace

int main(int argc, char** argv) {
    std::signal(SIGABRT, on_abort);
    int seconds = 60;
    std::string only;
    std::vector<std::string> files;
    for (int i = 1; i < argc; i++) {
        std::string a = argv[i];
        if (a == "--seconds" && i + 1 < argc) seconds = std::stoi(argv[++i]);
        else if (a == "--target" && i + 1 < argc) only = argv[++i];
        else if (a == "--crash-file" && i + 1 < argc) g_crash_file = argv[++i];
        else files.push_back(a);
    }
    const auto& targets = fuzz::targets();
    if (!files.empty()) {  // replay
        for (const auto& f : files) {
            std::ifstream in(f, std::ios::binary);
            g_current.assign(std::istreambuf_iterator<char>(in), {});
            fuzz::run_one(g_current.data(), g_current.size());
            std::cout << "replayed " << f << " (" << g_current.size() << " bytes): no crash\n";
        }
        return 0;
    }
    // First, every seed as it is: each must be accepted, or the seed is wrong and fuzzing from it is wasted.
    bool seeds_ok = true;
    for (size_t t = 0; t < targets.size(); t++) {
        if (!only.empty() && targets[t].name != only) continue;
        auto seeds = targets[t].seeds();
        size_t accepted = 0;
        for (size_t i = 0; i < seeds.size(); i++) {
            g_current = seeds[i];
            if (targets[t].run(seeds[i].data(), seeds[i].size())) accepted++;
            else std::cout << "  seed " << i << " of " << targets[t].name << " is not accepted\n";
        }
        std::cout << targets[t].name << ": " << accepted << " of " << seeds.size() << " seeds accepted\n";
        seeds_ok &= accepted == seeds.size();
    }
    // Then mutations, spread over the targets, for the time given.
    Rng rng;
    std::vector<std::vector<uint8_t>> pool;
    std::vector<size_t> owner;
    for (size_t t = 0; t < targets.size(); t++) {
        if (!only.empty() && targets[t].name != only) continue;
        for (auto& s : targets[t].seeds()) {
            std::vector<uint8_t> in{static_cast<uint8_t>(t)};
            in.insert(in.end(), s.begin(), s.end());
            pool.push_back(std::move(in));
            owner.push_back(t);
        }
    }
    std::vector<uint64_t> runs(targets.size(), 0), accepted(targets.size(), 0);
    const auto until = std::chrono::steady_clock::now() + std::chrono::seconds(seconds);
    uint64_t total = 0;
    while (!pool.empty() && std::chrono::steady_clock::now() < until) {
        for (int k = 0; k < 200; k++) {
            const size_t pick = rng.below(pool.size());
            g_current = pool[pick];
            mutate(g_current, rng);
            if (g_current.empty()) continue;
            g_current[0] = static_cast<uint8_t>(owner[pick]);  // keep it aimed at the same target
            const size_t t = owner[pick];
            runs[t]++;
            if (targets[t].run(g_current.data() + 1, g_current.size() - 1)) accepted[t]++;
            total++;
        }
    }
    for (size_t t = 0; t < targets.size(); t++)
        if (runs[t]) std::cout << targets[t].name << ": " << runs[t] << " mutated inputs, " << accepted[t] << " still accepted\n";
    std::cout << total << " inputs, no crashes and no round-trip failures" << (seeds_ok ? "" : " (but some seeds were not accepted: fix them)") << "\n";
    return seeds_ok ? 0 : 1;
}
