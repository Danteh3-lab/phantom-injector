#include "phantom/MemoryInspector.hpp"
#include <windows.h>
#include <iostream>
#include <limits>
#include <stdexcept>

namespace {
void Check(bool condition, const char* message) {
    if (!condition) throw std::runtime_error(message);
}
class Allocation {
public:
    explicit Allocation(std::size_t size) : data_(VirtualAlloc(nullptr, size, MEM_RESERVE, PAGE_NOACCESS)) {
        Check(data_ != nullptr, "reserve allocation");
    }
    ~Allocation() { VirtualFree(data_, 0, MEM_RELEASE); }
    Allocation(const Allocation&) = delete;
    Allocation& operator=(const Allocation&) = delete;
    std::uintptr_t address() const { return reinterpret_cast<std::uintptr_t>(data_); }
    void Commit(std::size_t offset, std::size_t size, DWORD protection) {
        Check(VirtualAlloc(reinterpret_cast<void*>(address() + offset), size, MEM_COMMIT, protection) != nullptr, "commit allocation");
    }
    void Protect(std::size_t offset, std::size_t size, DWORD protection) {
        DWORD previous = 0;
        Check(VirtualProtect(reinterpret_cast<void*>(address() + offset), size, protection, &previous) != 0, "protect allocation");
    }
private:
    void* data_;
};
}
int main() {
    try {
        using phantom::MemoryStatus;
        SYSTEM_INFO info{};
        GetSystemInfo(&info);
        const std::size_t page = info.dwPageSize;
        Allocation allocation(page * 4);
        const auto base = allocation.address();
        allocation.Commit(0, page * 2, PAGE_READWRITE);
        allocation.Commit(page * 2, page, PAGE_READWRITE);
        auto* bytes = reinterpret_cast<std::byte*>(base);
        for (std::size_t i = 0; i < page * 3; ++i) bytes[i] = std::byte(i & 0xff);
        allocation.Protect(page, page, PAGE_READONLY);
        allocation.Protect(page * 2, page, PAGE_READWRITE | PAGE_GUARD);
        phantom::MemoryInspector inspector;
        const auto regions = inspector.Enumerate(base + 1, page * 4 - 2);
        Check(regions.error.status == MemoryStatus::ok && regions.regions.size() == 4, "enumerate real split regions");
        Check(regions.regions[0].allocation_base == base && regions.regions[0].state == MEM_COMMIT &&
            regions.regions[0].type == MEM_PRIVATE && regions.regions[1].protection == PAGE_READONLY &&
            regions.regions[3].state == MEM_RESERVE, "native region metadata");
        const auto read = inspector.Read(base + page - 17, 34);
        Check(read.error.status == MemoryStatus::ok && read.bytes.size() == 34, "cross RW/RO boundary read");
        for (std::size_t i = 0; i < read.bytes.size(); ++i)
            Check(read.bytes[i] == std::byte((page - 17 + i) & 0xff), "real copied content");
        const auto guard = inspector.Read(base + page * 2 - 8, 16);
        Check(guard.error.status == MemoryStatus::unreadable && guard.bytes.size() == 8 &&
            guard.error.address == base + page * 2, "guard stops read with prefix");
        MEMORY_BASIC_INFORMATION guarded{};
        Check(VirtualQuery(reinterpret_cast<void*>(base + page * 2), &guarded, sizeof(guarded)) != 0 &&
            (guarded.Protect & PAGE_GUARD) != 0, "inspection does not clear stable guard page");
        Check(inspector.Read(base + page * 3, 1).error.status == MemoryStatus::unreadable, "reserved page rejected");
        allocation.Protect(page * 2, page, PAGE_NOACCESS);
        Check(inspector.Read(base + page * 2, 1).error.status == MemoryStatus::unreadable, "noaccess rejected");
        allocation.Protect(page * 2, page, PAGE_EXECUTE);
        Check(inspector.Read(base + page * 2, 1).error.status == MemoryStatus::unreadable, "execute-only rejected by policy");
        Check(VirtualFree(reinterpret_cast<void*>(base + page), page, MEM_DECOMMIT) != 0, "decommit test page");
        Check(inspector.Read(base + page, 1).error.status == MemoryStatus::unreadable, "decommitted page rejected");
        Check(inspector.Read(1, 1).bytes.empty(), "unmapped address cannot crash reader");
        Check(inspector.Enumerate(std::numeric_limits<std::uintptr_t>::max() - 1, 1).error.status == MemoryStatus::query_error,
            "above application address returns native query failure");
        std::cout << "Windows current-process memory checks passed\n";
        return 0;
    } catch (const std::exception& error) { std::cerr << error.what() << '\n'; return 1; }
}
