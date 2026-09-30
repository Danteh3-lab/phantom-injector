#pragma once
#include "phantom/MemoryInspector.hpp"
#include <string_view>

namespace phantom {
struct PatternByte {
    std::byte value;
    bool wildcard;
};

class Pattern {
public:
    // Whitespace-separated hex pairs, ? or ??. Throws std::invalid_argument
    // for malformed/empty input, >64 KiB text or >4096 pattern bytes.
    static Pattern Parse(std::string_view signature);
    const std::vector<PatternByte>& bytes() const noexcept { return bytes_; }
private:
    explicit Pattern(std::vector<PatternByte> bytes);
    std::vector<PatternByte> bytes_;
    std::vector<std::size_t> fixed_indices_;
    friend class PatternScanner;
};

enum class ScanStatus { ok, invalid_range, invalid_options, range_limit, match_limit, work_limit, memory_error };
struct ScanOptions {
    std::size_t chunk_size = 64 * 1024; // Must be in [1, 1 MiB].
    std::size_t max_scan_bytes = 64 * 1024 * 1024;
    std::size_t max_matches = 1024; // Stop immediately when reached.
    std::size_t max_comparisons = 64 * 1024 * 1024;
    std::size_t max_regions = 65536;
};
struct ScanResult {
    std::vector<std::uintptr_t> matches; // Ascending runtime addresses, overlaps included.
    ScanStatus status = ScanStatus::ok; // Only ok means the walk completed.
    MemoryError memory_error; // Underlying inspection failure when present.
    std::size_t bytes_read = 0;
    std::size_t bytes_skipped = 0; // Snapshot regions rejected as unreadable.
    std::size_t comparisons = 0; // Fixed-byte comparisons only.
};

class PatternScanner {
public:
    // Inspector must outlive this scanner. No direct memory access in the scanner.
    explicit PatternScanner(const MemoryInspector& inspector) : inspector_(inspector) {}
    ScanResult Scan(std::uintptr_t address, std::size_t size, const Pattern& pattern,
        const ScanOptions& options = {}) const;
private:
    const MemoryInspector& inspector_;
};
}
