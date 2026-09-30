#pragma once
#include <cstddef>
#include <cstdint>
#include <vector>

namespace phantom {
struct MemoryRegion {
    std::uintptr_t base = 0;
    std::uintptr_t allocation_base = 0;
    std::size_t size = 0;
    // Native Win32 MEM_* and PAGE_* values, retained without loss.
    std::uint32_t state = 0;
    std::uint32_t protection = 0;
    std::uint32_t type = 0;
    bool readable() const noexcept;
};

enum class MemoryStatus { ok, invalid_range, unreadable, query_error, read_error, limit_exceeded };
struct MemoryError {
    MemoryStatus status = MemoryStatus::ok;
    std::uintptr_t address = 0; // First uninspected byte on failure.
    std::uint32_t native_error = 0; // Win32 error when available.
};
struct RegionResult {
    std::vector<MemoryRegion> regions; // Empty on failure; full region metadata on success.
    MemoryError error;
};
struct ReadResult {
    std::vector<std::byte> bytes; // Only the copied contiguous prefix; check error.status.
    MemoryError error;
};
struct MemoryCopyResult {
    std::size_t bytes_read = 0;
    std::uint32_t native_error = 0;
};

// Test seam. Query may throw std::system_error. Copy must never dereference an
// unvalidated source directly and must report only bytes actually copied.
class MemoryBackend {
public:
    virtual ~MemoryBackend() = default;
    virtual MemoryRegion Query(std::uintptr_t address) const = 0;
    virtual MemoryCopyResult Copy(std::uintptr_t address, std::byte* output, std::size_t size) const = 0;
};

class MemoryInspector {
public:
#ifdef _WIN32
    MemoryInspector(); // Current process only, no owned handles.
#endif
    // Backend must outlive inspector. Production Windows uses the default constructor.
    explicit MemoryInspector(const MemoryBackend& backend) : backend_(backend) {}
    RegionResult Enumerate(std::uintptr_t address, std::size_t size,
        std::size_t max_regions = 65536) const;
    ReadResult Read(std::uintptr_t address, std::size_t size,
        std::size_t max_bytes = 16 * 1024 * 1024) const;
private:
    const MemoryBackend& backend_;
};
}
