#include "phantom/Logger.hpp"
#include <fstream>
#include <sstream>
#include <stdexcept>

namespace phantom {
namespace {
std::string Escape(const std::string& value) {
    std::ostringstream out;
    for (const unsigned char c : value) {
        if (c == '\\') out << "\\\\";
        else if (c == '\t') out << "\\t";
        else if (c == '\r') out << "\\r";
        else if (c == '\n') out << "\\n";
        else if (c < 0x20 || c == 0x7f) {
            constexpr char hex[] = "0123456789abcdef";
            out << "\\x" << hex[c >> 4] << hex[c & 15];
        } else out << static_cast<char>(c);
    }
    return out.str();
}
}

std::string FormatModules(const std::vector<ModuleInfo>& modules) {
    std::ostringstream out;
    out << "PhantomDumper v0.1 snapshot modules=" << modules.size() << '\n';
    out << "name\tbase_address\timage_size\tpath\n";
    for (const auto& module : modules) {
        out << Escape(module.name) << "\t0x" << std::hex << module.base
            << "\t0x" << module.image_size << std::dec << '\t' << Escape(module.path) << '\n';
    }
    return out.str();
}

void AppendModules(const std::filesystem::path& path, const std::vector<ModuleInfo>& modules) {
    const auto text = FormatModules(modules);
    std::ofstream file;
    file.exceptions(std::ios::failbit | std::ios::badbit);
    file.open(path, std::ios::binary | std::ios::app);
    file.write(text.data(), static_cast<std::streamsize>(text.size()));
    file.close(); // Check final flush/close errors before reporting success.
}
}
