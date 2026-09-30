#pragma once
#include <cstdint>
#include <string>
#include <vector>

namespace phantom {
struct ModuleInfo {
    std::string name; // UTF-8
    std::string path; // UTF-8; Tool Help's fixed-size path may be truncated.
    std::uintptr_t base;
    std::uint32_t image_size;
};

// Current process only. Copies snapshot metadata; never dereferences image memory.
// Throws std::system_error on failure; partial enumeration is never returned.
std::vector<ModuleInfo> EnumerateModules();
}
