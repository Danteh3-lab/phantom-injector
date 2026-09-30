#include "phantom/PatternScanner.hpp"
#include <algorithm>
#include <iostream>
#include <limits>
#include <random>
#include <stdexcept>
#include <string>
#include <system_error>
#include <utility>

namespace {
void Check(bool condition, const char* message) {
    if (!condition) throw std::runtime_error(message);
}
void Reject(std::string_view text) {
    try { (void)phantom::Pattern::Parse(text); }
    catch (const std::invalid_argument&) { return; }
    throw std::runtime_error("malformed pattern accepted");
}
class Fixture final : public phantom::MemoryBackend {
public:
    static constexpr std::uintptr_t base = 0x123456780000ULL;
    std::vector<std::byte> data;
    std::vector<phantom::MemoryRegion> regions;
    mutable std::size_t copies = 0;
    mutable std::size_t queries = 0;
    mutable std::size_t largest_copy = 0;
    std::uintptr_t query_failure = 0;
    std::uintptr_t copy_failure = 0;
    std::size_t partial_bytes = 0;
    explicit Fixture(std::vector<std::byte> bytes) : data(std::move(bytes)) {
        regions.push_back({base, base, data.size(), 0x1000, 0x04, 0x20000});
    }
    phantom::MemoryRegion Query(std::uintptr_t address) const override {
        ++queries;
        if (address != query_failure) {
            for (const auto& region : regions)
                if (address >= region.base && address - region.base < region.size) return region;
        }
        throw std::system_error(487, std::system_category(), "synthetic query failure");
    }
    phantom::MemoryCopyResult Copy(std::uintptr_t address, std::byte* output, std::size_t size) const override {
        ++copies;
        largest_copy = std::max(largest_copy, size);
        const auto offset = static_cast<std::size_t>(address - base);
        Check(offset <= data.size() && size <= data.size() - offset, "copy within fixture");
        const auto count = address == copy_failure ? std::min(size, partial_bytes) : size;
        std::copy_n(data.data() + offset, count, output);
        return {count, address == copy_failure ? 299u : 0u};
    }
};
std::vector<std::byte> Bytes(std::initializer_list<unsigned int> values) {
    std::vector<std::byte> result;
    for (const auto value : values) result.push_back(std::byte(value));
    return result;
}
std::vector<std::uintptr_t> Reference(const Fixture& fixture, const phantom::Pattern& pattern) {
    std::vector<std::uintptr_t> matches;
    for (std::size_t i = 0; i + pattern.bytes().size() <= fixture.data.size(); ++i) {
        bool match = true;
        for (std::size_t j = 0; j < pattern.bytes().size(); ++j) {
            const auto address = Fixture::base + i + j;
            const auto region = std::find_if(fixture.regions.begin(), fixture.regions.end(), [&](const auto& item) {
                return address >= item.base && address - item.base < item.size;
            });
            if (region == fixture.regions.end() || !region->readable() ||
                (!pattern.bytes()[j].wildcard && fixture.data[i + j] != pattern.bytes()[j].value)) { match = false; break; }
        }
        if (match) matches.push_back(Fixture::base + i);
    }
    return matches;
}
}

int main() {
    try {
        using phantom::Pattern;
        using phantom::ScanStatus;
        const auto parsed = Pattern::Parse("\t48\r\n8b ? ?? 00 Ff\f\v");
        Check(parsed.bytes().size() == 6 && parsed.bytes()[0].value == std::byte{0x48} &&
            parsed.bytes()[1].value == std::byte{0x8b} && parsed.bytes()[2].wildcard &&
            parsed.bytes()[3].wildcard && !parsed.bytes()[4].wildcard && parsed.bytes()[5].value == std::byte{0xff},
            "case, whitespace and whole-byte wildcards parsed");
        for (const auto bad : {"", " \t\r\n", "4", "488B", "0x48", "GG", "?F", "F?", "???", "48,8B", "-1", "100"}) Reject(bad);
        Reject(std::string("48\0 8B", 6));
        Reject(std::string(1, static_cast<char>(0xff)));
        Reject(std::string(65537, ' '));
        std::string longest;
        for (int i = 0; i < 4096; ++i) longest += "00 ";
        Check(Pattern::Parse(longest).bytes().size() == 4096, "maximum pattern accepted");
        Reject(longest + "00");

        Fixture fixture(Bytes({0xaa, 0xaa, 0xaa, 0x00, 0x48, 0x8b, 0x11, 0x89, 0xff}));
        phantom::MemoryInspector inspector(fixture);
        phantom::PatternScanner scanner(inspector);
        const auto base = Fixture::base;
        const auto overlap = scanner.Scan(base, fixture.data.size(), Pattern::Parse("AA AA"));
        Check(overlap.status == ScanStatus::ok && overlap.matches == std::vector<std::uintptr_t>{base, base + 1}, "overlapping matches at 64-bit runtime addresses");
        Check(scanner.Scan(base, fixture.data.size(), Pattern::Parse("00")).matches == std::vector<std::uintptr_t>{base + 3}, "NUL is an exact byte");
        Check(scanner.Scan(base, fixture.data.size(), Pattern::Parse("FF")).matches == std::vector<std::uintptr_t>{base + 8}, "match at last byte");
        const auto signature = Pattern::Parse("48 8B ?? 89 FF");
        phantom::ScanOptions options;
        options.chunk_size = 1;
        const auto small = scanner.Scan(base, fixture.data.size(), signature, options);
        Check(small.status == ScanStatus::ok && small.matches == std::vector<std::uintptr_t>{base + 4} && small.bytes_read == fixture.data.size(), "pattern longer than chunk crosses multiple reads");
        Check(scanner.Scan(base + 5, 4, signature, options).matches.empty(), "match cannot start before requested range");
        Check(scanner.Scan(base + 4, 4, signature, options).matches.empty(), "match cannot extend beyond requested range");
        Check(scanner.Scan(base, fixture.data.size(), Pattern::Parse("DE AD")).matches.empty(), "no-match result");
        const auto wild = scanner.Scan(base, fixture.data.size(), Pattern::Parse("? ??"), options);
        Check(wild.status == ScanStatus::ok && wild.matches.size() == fixture.data.size() - 1 && wild.comparisons == 0, "all-wildcard matches are bounded by range");

        const auto calls = fixture.queries;
        Check(scanner.Scan(0, 0, signature).status == ScanStatus::ok, "empty scan succeeds");
        Check(scanner.Scan(0, 1, signature).status == ScanStatus::invalid_range, "null scan rejected");
        Check(scanner.Scan(std::numeric_limits<std::uintptr_t>::max() - 1, 2, signature).status == ScanStatus::invalid_range, "overflow rejected");
        options.max_scan_bytes = fixture.data.size() - 1;
        Check(scanner.Scan(base, fixture.data.size(), signature, options).status == ScanStatus::range_limit, "range cap checked before backend");
        options = {};
        options.chunk_size = 0;
        Check(scanner.Scan(base, 1, signature, options).status == ScanStatus::invalid_options, "zero chunk rejected");
        options.chunk_size = 1024 * 1024 + 1;
        Check(scanner.Scan(base, 1, signature, options).status == ScanStatus::invalid_options, "excessive chunk rejected");
        options = {}; options.max_matches = 0;
        Check(scanner.Scan(base, 1, signature, options).status == ScanStatus::invalid_options, "zero match cap rejected");
        options = {}; options.max_comparisons = 0;
        Check(scanner.Scan(base, 1, signature, options).status == ScanStatus::invalid_options, "zero work cap rejected");
        options = {}; options.max_regions = 0;
        Check(scanner.Scan(base, 1, signature, options).status == ScanStatus::invalid_options, "zero region cap rejected");
        Check(fixture.queries == calls, "invalid, empty and over-limit requests have no memory side effects");
        options = {}; options.max_matches = 2;
        const auto capped = scanner.Scan(base, fixture.data.size(), Pattern::Parse("??"), options);
        Check(capped.status == ScanStatus::match_limit && capped.matches == std::vector<std::uintptr_t>{base, base + 1}, "match cap never claims a complete scan");
        options = {}; options.max_comparisons = 2;
        const auto budget = scanner.Scan(base, fixture.data.size(), Pattern::Parse("AA AA"), options);
        Check(budget.status == ScanStatus::work_limit && budget.comparisons == 2 && budget.matches == std::vector<std::uintptr_t>{base}, "work cap preserves prior matches");

        // Two adjacent readable regions retain overlap even when allocations differ.
        fixture.regions = {{base, base, 6, 0x1000, 0x04, 0x20000}, {base + 6, base + 6, 3, 0x1000, 0x02, 0x20000}};
        options = {}; options.chunk_size = 3;
        const auto split = scanner.Scan(base, fixture.data.size(), signature, options);
        Check(split.status == ScanStatus::ok && split.matches == std::vector<std::uintptr_t>{base + 4}, "readable region boundary match");
        Check(fixture.largest_copy <= 64 * 1024, "copies stay within configured/default bounds");
        options.max_regions = 1;
        const auto region_cap = scanner.Scan(base, fixture.data.size(), signature, options);
        Check(region_cap.status == ScanStatus::memory_error && region_cap.memory_error.status == phantom::MemoryStatus::limit_exceeded && region_cap.matches.empty(), "enumeration cap propagated");

        Fixture gap(Bytes({0xaa, 0xbb, 0x00, 0xcc, 0xdd}));
        gap.regions = {{base, base, 2, 0x1000, 0x04, 0x20000}, {base + 2, base, 1, 0x1000, 0x104, 0x20000},
            {base + 3, base, 2, 0x1000, 0x02, 0x20000}};
        phantom::MemoryInspector gap_inspector(gap);
        phantom::PatternScanner gap_scanner(gap_inspector);
        const auto across_gap = gap_scanner.Scan(base, gap.data.size(), Pattern::Parse("BB CC"));
        Check(across_gap.status == ScanStatus::ok && across_gap.matches.empty() && across_gap.bytes_skipped == 1 && across_gap.bytes_read == 4 && gap.copies == 2, "unreadable gap is not concatenated or read");
        Check(gap_scanner.Scan(base, gap.data.size(), Pattern::Parse("AA ?")).matches == std::vector<std::uintptr_t>{base} &&
            gap_scanner.Scan(base, gap.data.size(), Pattern::Parse("CC DD")).matches == std::vector<std::uintptr_t>{base + 3}, "matches on both sides of gap");
        gap.regions[0].protection = 0x01;
        gap.regions[2].state = 0x2000;
        const auto inaccessible = gap_scanner.Scan(base, gap.data.size(), Pattern::Parse("?"));
        Check(inaccessible.status == ScanStatus::ok && inaccessible.matches.empty() && inaccessible.bytes_read == 0 && inaccessible.bytes_skipped == 5, "fully inaccessible range skipped");

        Fixture failures(Bytes({0xaa, 0xbb, 0xcc, 0xdd, 0xee, 0xff}));
        phantom::MemoryInspector failure_inspector(failures);
        phantom::PatternScanner failure_scanner(failure_inspector);
        options = {}; options.chunk_size = 3;
        failures.copy_failure = base + 3; failures.partial_bytes = 2;
        const auto partial = failure_scanner.Scan(base, failures.data.size(), Pattern::Parse("CC DD EE"), options);
        Check(partial.status == ScanStatus::memory_error && partial.memory_error.status == phantom::MemoryStatus::read_error &&
            partial.memory_error.native_error == 299 && partial.memory_error.address == base + 5 && partial.bytes_read == 5 &&
            partial.matches == std::vector<std::uintptr_t>{base + 2}, "match within copied prefix retained with native failure");
        options.max_matches = 1;
        const auto error_at_cap = failure_scanner.Scan(base, failures.data.size(), Pattern::Parse("CC DD EE"), options);
        Check(error_at_cap.status == ScanStatus::memory_error && error_at_cap.memory_error.native_error == 299,
            "native read failure takes priority over match cap in its prefix");
        options.max_matches = 1024;
        options.max_comparisons = 1;
        // First chunk cannot yet fit a five-byte pattern; failed prefix consumes
        // one comparison before stopping at the budget, retaining native error.
        const auto error_at_work_cap = failure_scanner.Scan(base, failures.data.size(), Pattern::Parse("? ? CC AA AA"), options);
        Check(error_at_work_cap.status == ScanStatus::memory_error && error_at_work_cap.memory_error.native_error == 299,
            "native read failure remains visible at comparison cap");
        options.max_comparisons = 64 * 1024 * 1024;
        Check(failure_scanner.Scan(base, failures.data.size(), Pattern::Parse("DD EE FF"), options).matches.empty(), "uncopied tail cannot match");
        failures.copy_failure = 0; failures.query_failure = base + 3;
        const auto churn = failure_scanner.Scan(base, failures.data.size(), Pattern::Parse("AA BB"), options);
        Check(churn.status == ScanStatus::memory_error && churn.memory_error.status == phantom::MemoryStatus::query_error &&
            churn.memory_error.native_error == 487 && churn.matches == std::vector<std::uintptr_t>{base}, "query failure after enumeration preserves earlier matches");
        failures.query_failure = base;
        const auto failed_walk = failure_scanner.Scan(base, failures.data.size(), signature);
        Check(failed_walk.status == ScanStatus::memory_error && failed_walk.bytes_read == 0 && failed_walk.matches.empty(), "enumeration failure performs no reads");

        // Compare streaming results with an independent whole-buffer oracle.
        std::mt19937 random(0x5048414e);
        for (int trial = 0; trial < 200; ++trial) {
            const auto size = static_cast<std::size_t>(random() % 64 + 1);
            Fixture sample(std::vector<std::byte>(size, std::byte{0}));
            for (auto& value : sample.data) value = std::byte(random() % 4);
            sample.regions.clear();
            for (std::size_t offset = 0; offset < size;) {
                const auto count = std::min(size - offset, static_cast<std::size_t>(random() % 8 + 1));
                const bool readable = random() % 4 != 0;
                sample.regions.push_back({base + offset, base, count, 0x1000, readable ? 0x04u : 0x01u, 0x20000});
                offset += count;
            }
            std::string text;
            const auto length = random() % 10 + 1;
            for (std::uint32_t i = 0; i < length; ++i) {
                if (random() % 3 == 0) text += "?? ";
                else { text += '0'; text += static_cast<char>('0' + random() % 4); text += ' '; }
            }
            const auto pattern = Pattern::Parse(text);
            phantom::MemoryInspector sample_inspector(sample);
            phantom::PatternScanner sample_scanner(sample_inspector);
            options = {}; options.chunk_size = random() % 12 + 1;
            const auto actual = sample_scanner.Scan(base, size, pattern, options);
            Check(actual.status == ScanStatus::ok && actual.matches == Reference(sample, pattern), "streaming matches agree with reference across randomized splits/gaps");
            Check(actual.bytes_read + actual.bytes_skipped == size && sample.largest_copy <= options.chunk_size, "coverage and copy bounds across randomized ranges");
        }
        std::cout << "PatternScanner checks passed\n";
        return 0;
    } catch (const std::exception& error) { std::cerr << error.what() << '\n'; return 1; }
}
