#include "phantom/PatternScanner.hpp"
#include <algorithm>
#include <limits>
#include <stdexcept>
#include <utility>

namespace phantom {
namespace {
bool Space(char value) {
    return value == ' ' || value == '\t' || value == '\r' || value == '\n' || value == '\f' || value == '\v';
}
int Hex(char value) {
    if (value >= '0' && value <= '9') return value - '0';
    if (value >= 'a' && value <= 'f') return value - 'a' + 10;
    if (value >= 'A' && value <= 'F') return value - 'A' + 10;
    return -1;
}
}

Pattern::Pattern(std::vector<PatternByte> bytes) : bytes_(std::move(bytes)) {
    for (std::size_t i = 0; i < bytes_.size(); ++i)
        if (!bytes_[i].wildcard) fixed_indices_.push_back(i);
}

Pattern Pattern::Parse(std::string_view signature) {
    if (signature.size() > 64 * 1024) throw std::invalid_argument("signature text exceeds 64 KiB");
    std::vector<PatternByte> bytes;
    std::size_t cursor = 0;
    while (cursor < signature.size()) {
        while (cursor < signature.size() && Space(signature[cursor])) ++cursor;
        if (cursor == signature.size()) break;
        const auto start = cursor;
        while (cursor < signature.size() && !Space(signature[cursor])) ++cursor;
        const auto token = signature.substr(start, cursor - start);
        if (bytes.size() == 4096) throw std::invalid_argument("pattern exceeds 4096 bytes");
        if (token == "?" || token == "??") bytes.push_back({std::byte{0}, true});
        else if (token.size() == 2 && Hex(token[0]) >= 0 && Hex(token[1]) >= 0)
            bytes.push_back({std::byte((Hex(token[0]) << 4) | Hex(token[1])), false});
        else throw std::invalid_argument("expected a hex byte, ? or ??");
    }
    if (bytes.empty()) throw std::invalid_argument("pattern is empty");
    return Pattern(std::move(bytes));
}

ScanResult PatternScanner::Scan(std::uintptr_t address, std::size_t size, const Pattern& pattern,
    const ScanOptions& options) const {
    ScanResult result;
    if (size > std::numeric_limits<std::uintptr_t>::max() - address || (address == 0 && size != 0)) {
        result.status = ScanStatus::invalid_range;
        return result;
    }
    // A moved-from Pattern is valid C++, but may no longer contain a signature.
    if (pattern.bytes_.empty() || options.chunk_size == 0 || options.chunk_size > 1024 * 1024 ||
        options.max_matches == 0 || options.max_comparisons == 0 || options.max_regions == 0) {
        result.status = ScanStatus::invalid_options;
        return result;
    }
    if (size > options.max_scan_bytes) { result.status = ScanStatus::range_limit; return result; }
    if (size == 0) return result;
    const auto regions = inspector_.Enumerate(address, size, options.max_regions);
    if (regions.error.status != MemoryStatus::ok) {
        result.status = ScanStatus::memory_error;
        result.memory_error = regions.error;
        return result;
    }
    const auto end = address + size;
    const auto length = pattern.bytes_.size();
    std::vector<std::byte> window;
    window.reserve(options.chunk_size + length - 1);
    auto cursor = address;
    for (const auto& region : regions.regions) {
        // Enumeration has checked every region's arithmetic and forward progress.
        const auto region_end = std::min(end, region.base + region.size);
        if (!region.readable()) {
            result.bytes_skipped += static_cast<std::size_t>(region_end - cursor);
            window.clear(); // Never manufacture a match across an inaccessible gap.
            cursor = region_end;
            continue;
        }
        while (cursor < region_end) {
            const auto count = std::min(options.chunk_size, static_cast<std::size_t>(region_end - cursor));
            const auto read = inspector_.Read(cursor, count, options.chunk_size);
            result.bytes_read += read.bytes.size();
            result.memory_error = read.error;
            const auto window_base = cursor - window.size();
            window.insert(window.end(), read.bytes.begin(), read.bytes.end());
            for (std::size_t start = 0; start + length <= window.size(); ++start) {
                bool matches = true;
                for (const auto index : pattern.fixed_indices_) {
                    if (result.comparisons == options.max_comparisons) {
                        result.status = read.error.status == MemoryStatus::ok ? ScanStatus::work_limit : ScanStatus::memory_error;
                        return result;
                    }
                    ++result.comparisons;
                    if (window[start + index] != pattern.bytes_[index].value) { matches = false; break; }
                }
                if (matches) {
                    result.matches.push_back(window_base + start);
                    if (result.matches.size() == options.max_matches) {
                        result.status = read.error.status == MemoryStatus::ok ? ScanStatus::match_limit : ScanStatus::memory_error;
                        return result;
                    }
                }
            }
            if (read.error.status != MemoryStatus::ok) {
                result.status = ScanStatus::memory_error;
                return result; // Matches in the copied prefix are valid observations.
            }
            const auto keep = std::min(length - 1, window.size());
            window.erase(window.begin(), window.end() - static_cast<std::ptrdiff_t>(keep));
            cursor += count;
        }
    }
    return result;
}
}
