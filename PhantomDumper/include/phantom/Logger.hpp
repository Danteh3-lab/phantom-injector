#pragma once
#include "ModuleResolver.hpp"
#include <filesystem>
#include <string>

namespace phantom {
std::string FormatModules(const std::vector<ModuleInfo>& modules);
// Opens, appends and closes per call. No file handles survive into DLL detach.
void AppendModules(const std::filesystem::path& path, const std::vector<ModuleInfo>& modules);
}
