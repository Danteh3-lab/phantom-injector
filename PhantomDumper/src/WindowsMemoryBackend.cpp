#include "phantom/MemoryInspector.hpp"
#include <windows.h>
#include <system_error>

namespace phantom {
namespace {
static_assert(MEM_COMMIT == 0x1000 && PAGE_GUARD == 0x100 && PAGE_READONLY == 0x02 &&
    PAGE_READWRITE == 0x04 && PAGE_WRITECOPY == 0x08 && PAGE_EXECUTE_READ == 0x20 &&
    PAGE_EXECUTE_READWRITE == 0x40 && PAGE_EXECUTE_WRITECOPY == 0x80,
    "portable protection classification must match Windows");
class CurrentProcessBackend final : public MemoryBackend {
public:
    MemoryRegion Query(std::uintptr_t address) const override {
        MEMORY_BASIC_INFORMATION info{};
        if (VirtualQuery(reinterpret_cast<const void*>(address), &info, sizeof(info)) == 0)
            throw std::system_error(static_cast<int>(GetLastError()), std::system_category(), "VirtualQuery");
        return {reinterpret_cast<std::uintptr_t>(info.BaseAddress),
            reinterpret_cast<std::uintptr_t>(info.AllocationBase), info.RegionSize,
            info.State, info.Protect, info.Type};
    }
    MemoryCopyResult Copy(std::uintptr_t address, std::byte* output, std::size_t size) const override {
        SIZE_T copied = 0;
        // Query is a snapshot, not a lifetime guarantee. Let Windows validate the
        // transfer again; no memcpy/SEH against potentially freed source pages.
        const BOOL success = ReadProcessMemory(GetCurrentProcess(), reinterpret_cast<const void*>(address),
            output, size, &copied);
        const DWORD error = success ? ERROR_SUCCESS : GetLastError();
        return {copied, success ? 0 : (error == ERROR_SUCCESS ? ERROR_PARTIAL_COPY : error)};
    }
};
const CurrentProcessBackend backend;
}
MemoryInspector::MemoryInspector() : backend_(backend) {}
}
