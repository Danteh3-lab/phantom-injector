#include "phantom/MemoryInspector.hpp"
#include <algorithm>
#include <iostream>
#include <limits>
#include <stdexcept>
#include <system_error>

namespace {
void Check(bool condition, const char* message) {
    if (!condition) throw std::runtime_error(message);
}
class FakeMemory final : public phantom::MemoryBackend {
public:
    std::vector<phantom::MemoryRegion> regions = {
        {0x1000, 0x1000, 4, 0x1000, 0x04, 0x20000},
        {0x1004, 0x1000, 4, 0x1000, 0x02, 0x20000}
    };
    mutable int queries = 0;
    mutable int copies = 0;
    std::uintptr_t query_failure = 0;
    std::uintptr_t copy_failure = 0;
    std::size_t partial_bytes = 0;
    bool malformed = false;
    bool oversized_copy = false;
    bool report_copy_error = true;
    phantom::MemoryRegion Query(std::uintptr_t address) const override {
        ++queries;
        if (malformed) return {address + 1, 0, 0, 0x1000, 0x04, 0};
        if (address != query_failure) {
            for (const auto& region : regions)
                if (address >= region.base && address - region.base < region.size) return region;
        }
        throw std::system_error(487, std::system_category(), "synthetic query failure");
    }
    phantom::MemoryCopyResult Copy(std::uintptr_t address, std::byte* output, std::size_t size) const override {
        ++copies;
        const auto count = address == copy_failure ? std::min(size, partial_bytes) : size;
        for (std::size_t i = 0; i < count; ++i) output[i] = std::byte((address + i) & 0xff);
        if (oversized_copy) return {size + 1, 0};
        return {count, address == copy_failure && report_copy_error ? 299u : 0u};
    }
};
}
int main() {
    try {
        using phantom::MemoryStatus;
        FakeMemory backend;
        phantom::MemoryInspector inspector(backend);
        for (const auto access : {0x02u, 0x04u, 0x08u, 0x20u, 0x40u, 0x80u}) {
            phantom::MemoryRegion region{0, 0, 1, 0x1000, access, 0};
            Check(region.readable(), "readable protection");
            region.protection |= 0x200; // PAGE_NOCACHE modifier.
            Check(region.readable(), "readable with modifier");
            region.protection |= 0x100;
            Check(!region.readable(), "guard always rejected");
        }
        for (const auto access : {0u, 0x01u, 0x10u, 0x03u})
            Check(!phantom::MemoryRegion{0, 0, 1, 0x1000, access, 0}.readable(), "unknown/noaccess/execute-only rejected");
        for (const auto state : {0u, 0x2000u, 0x10000u})
            Check(!phantom::MemoryRegion{0, 0, 1, state, 0x04, 0}.readable(), "uncommitted rejected");

        const auto regions = inspector.Enumerate(0x1001, 6);
        Check(regions.error.status == MemoryStatus::ok && regions.regions.size() == 2, "unaligned enumeration crosses regions");
        Check(regions.regions.front().base == 0x1000 && regions.regions.front().size == 4 &&
            regions.regions.back().allocation_base == 0x1000 && regions.regions.back().type == 0x20000,
            "enumeration preserves full native metadata");
        const auto read = inspector.Read(0x1001, 6);
        Check(read.error.status == MemoryStatus::ok && read.bytes.size() == 6, "cross-region read");
        for (std::size_t i = 0; i < read.bytes.size(); ++i)
            Check(read.bytes[i] == std::byte(i + 1), "exact contiguous byte content");
        const auto copies = backend.copies;
        const auto queries = backend.queries;
        Check(inspector.Read(0, 0).error.status == MemoryStatus::ok && inspector.Enumerate(0, 0, 0).regions.empty(), "empty operations succeed");
        Check(inspector.Read(0, 1).error.status == MemoryStatus::invalid_range, "null nonempty read rejected");
        const auto max = std::numeric_limits<std::uintptr_t>::max();
        Check(inspector.Read(max - 1, 2).error.status == MemoryStatus::invalid_range &&
            inspector.Enumerate(max, 1).error.status == MemoryStatus::invalid_range, "overflow rejected");
        Check(inspector.Read(0x1000, 8, 7).error.status == MemoryStatus::limit_exceeded, "bounded allocation");
        Check(backend.copies == copies && backend.queries == queries, "invalid/empty/oversized reads never touch backend");
        Check(inspector.Read(0x1000, 8, 8).bytes.size() == 8, "exact allocation limit allowed");
        const auto limited = inspector.Enumerate(0x1000, 8, 1);
        Check(limited.error.status == MemoryStatus::limit_exceeded && limited.error.address == 0x1004 && limited.regions.empty(), "region limit discards partial walk");
        Check(inspector.Enumerate(0x1000, 4, 0).error.status == MemoryStatus::limit_exceeded, "zero region limit");

        backend.regions.back().protection = 0x104;
        const auto guarded = inspector.Read(0x1002, 5);
        Check(guarded.error.status == MemoryStatus::unreadable && guarded.error.address == 0x1004 && guarded.bytes.size() == 2,
            "guarded range preserves copied prefix");
        Check(inspector.Enumerate(0x1000, 8).regions.size() == 2, "metadata enumeration includes inaccessible regions");
        backend.regions.back().protection = 0x02;
        backend.query_failure = 0x1004;
        const auto query = inspector.Read(0x1000, 8);
        Check(query.error.status == MemoryStatus::query_error && query.error.native_error == 487 && query.bytes.size() == 4, "read query failure retains prefix/native error");
        const auto failed_walk = inspector.Enumerate(0x1000, 8);
        Check(failed_walk.error.status == MemoryStatus::query_error && failed_walk.regions.empty(), "failed walk never returns partial metadata");
        backend.query_failure = 0;
        backend.copy_failure = 0x1004;
        backend.partial_bytes = 2;
        const auto partial = inspector.Read(0x1000, 8);
        Check(partial.error.status == MemoryStatus::read_error && partial.error.native_error == 299 &&
            partial.error.address == 0x1006 && partial.bytes.size() == 6 && partial.bytes.back() == std::byte{5},
            "partial native transfer exposes only copied bytes");
        backend.partial_bytes = 0;
        Check(inspector.Read(0x1004, 4).bytes.empty(), "query/copy protection race returns failure without dereference");
        backend.report_copy_error = false;
        Check(inspector.Read(0x1004, 4).error.status == MemoryStatus::read_error, "short transfer with no native error rejected");
        backend.report_copy_error = true;
        backend.partial_bytes = 4;
        const auto failed_full = inspector.Read(0x1004, 4);
        Check(failed_full.error.status == MemoryStatus::read_error && failed_full.bytes.size() == 4,
            "native failure remains failure even when all bytes reported copied");
        backend.copy_failure = 0;
        backend.oversized_copy = true;
        Check(inspector.Read(0x1000, 4).error.status == MemoryStatus::read_error && inspector.Read(0x1000, 4).bytes.empty(), "invalid backend transfer rejected");
        backend.oversized_copy = false;
        backend.malformed = true;
        Check(inspector.Read(0x1000, 4).error.status == MemoryStatus::query_error &&
            inspector.Enumerate(0x1000, 4).error.status == MemoryStatus::query_error, "malformed query cannot loop");
        backend.malformed = false;
        backend.regions.front().size = 0;
        Check(inspector.Read(0x1000, 1).error.status == MemoryStatus::query_error, "missing region fails closed");
        backend.regions = {{max - 2, 0, 4, 0x1000, 0x04, 0}};
        Check(inspector.Read(max - 2, 1).error.status == MemoryStatus::query_error, "overflowing native region rejected");
        std::cout << "MemoryInspector portable checks passed\n";
        return 0;
    } catch (const std::exception& error) { std::cerr << error.what() << '\n'; return 1; }
}
