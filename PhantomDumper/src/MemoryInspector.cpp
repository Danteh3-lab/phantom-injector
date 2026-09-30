#include "phantom/MemoryInspector.hpp"
#include <algorithm>
#include <limits>
#include <system_error>

namespace phantom {
namespace {
bool RangeEnd(std::uintptr_t address, std::size_t size, std::uintptr_t& end) {
    if (size > std::numeric_limits<std::uintptr_t>::max() - address) return false;
    end = address + size;
    return true;
}
bool RegionEnd(const MemoryRegion& region, std::uintptr_t cursor, std::uintptr_t& end) {
    return region.size != 0 && region.base <= cursor && RangeEnd(region.base, region.size, end) && end > cursor;
}
std::uint32_t NativeError(const std::system_error& error) {
    return static_cast<std::uint32_t>(error.code().value());
}
}

bool MemoryRegion::readable() const noexcept {
    // MEM_COMMIT, PAGE_GUARD. Unknown/execute-only/no-access protections fail closed.
    if (state != 0x1000 || (protection & 0x100) != 0) return false;
    switch (protection & 0xff) {
    case 0x02: case 0x04: case 0x08: case 0x20: case 0x40: case 0x80: return true;
    default: return false;
    }
}

RegionResult MemoryInspector::Enumerate(std::uintptr_t address, std::size_t size, std::size_t max_regions) const {
    RegionResult result;
    std::uintptr_t end = 0;
    if (!RangeEnd(address, size, end)) return {{}, {MemoryStatus::invalid_range, address, 0}};
    auto cursor = address;
    while (cursor < end) {
        if (result.regions.size() == max_regions) return {{}, {MemoryStatus::limit_exceeded, cursor, 0}};
        MemoryRegion region;
        try { region = backend_.Query(cursor); }
        catch (const std::system_error& error) { return {{}, {MemoryStatus::query_error, cursor, NativeError(error)}}; }
        std::uintptr_t region_end = 0;
        if (!RegionEnd(region, cursor, region_end)) return {{}, {MemoryStatus::query_error, cursor, 0}};
        result.regions.push_back(region);
        cursor = std::min(end, region_end);
    }
    return result;
}

ReadResult MemoryInspector::Read(std::uintptr_t address, std::size_t size, std::size_t max_bytes) const {
    ReadResult result;
    std::uintptr_t end = 0;
    if (!RangeEnd(address, size, end) || (address == 0 && size != 0))
        return {{}, {MemoryStatus::invalid_range, address, 0}};
    if (size > max_bytes) return {{}, {MemoryStatus::limit_exceeded, address, 0}};
    if (size == 0) return result;
    result.bytes.resize(size);
    std::size_t copied = 0;
    std::size_t queries = 0;
    while (copied < size) {
        const auto cursor = address + copied;
        if (++queries > 65536) {
            result.error = {MemoryStatus::limit_exceeded, cursor, 0};
            break;
        }
        MemoryRegion region;
        try { region = backend_.Query(cursor); }
        catch (const std::system_error& error) {
            result.error = {MemoryStatus::query_error, cursor, NativeError(error)};
            break;
        }
        std::uintptr_t region_end = 0;
        if (!RegionEnd(region, cursor, region_end)) {
            result.error = {MemoryStatus::query_error, cursor, 0};
            break;
        }
        if (!region.readable()) {
            result.error = {MemoryStatus::unreadable, cursor, 0};
            break;
        }
        const auto count = static_cast<std::size_t>(std::min(end, region_end) - cursor);
        const auto transfer = backend_.Copy(cursor, result.bytes.data() + copied, count);
        if (transfer.bytes_read > count) {
            result.error = {MemoryStatus::read_error, cursor, transfer.native_error};
            break;
        }
        copied += transfer.bytes_read;
        if (transfer.native_error != 0 || transfer.bytes_read != count) {
            result.error = {MemoryStatus::read_error, address + copied, transfer.native_error};
            break;
        }
    }
    result.bytes.resize(copied);
    return result;
}
}
