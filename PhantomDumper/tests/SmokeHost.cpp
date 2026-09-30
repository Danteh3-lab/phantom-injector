#include <windows.h>
#include <cstdint>
#include <cstring>
#include <filesystem>
#include <fstream>
#include <iostream>
#include <iterator>
#include <sstream>
#include <stdexcept>
#include <string>

namespace {
void Check(bool condition, const char* message) {
    if (!condition) throw std::runtime_error(message);
}
struct Fixture {
    std::filesystem::path directory = std::filesystem::temp_directory_path() /
        (L"phantom-smoke-\u6d4b\u8bd5-" + std::to_wstring(GetCurrentProcessId()));
    Fixture() { Check(std::filesystem::create_directory(directory), "create Unicode fixture directory"); }
    ~Fixture() { std::error_code error; std::filesystem::remove_all(directory, error); }
};
class Library {
public:
    explicit Library(const std::filesystem::path& path) : module_(LoadLibraryW(path.c_str())) {
        Check(module_ != nullptr, "LoadLibraryW");
    }
    ~Library() { FreeLibrary(module_); }
    template<class Function> Function Get(const char* name) {
        const auto address = GetProcAddress(module_, name);
        Check(address != nullptr, name);
        // Avoid MSVC C4191 with the Win32 function-pointer conversion idiom.
        static_assert(sizeof(Function) == sizeof(address));
        Function function;
        std::memcpy(&function, &address, sizeof(function));
        return function;
    }
    std::uintptr_t base() const { return reinterpret_cast<std::uintptr_t>(module_); }
private:
    HMODULE module_;
};
std::string Read(const std::filesystem::path& path) {
    std::ifstream file(path, std::ios::binary);
    Check(file.good(), "log exists");
    return {std::istreambuf_iterator<char>(file), std::istreambuf_iterator<char>()};
}
std::string RowBase(std::uintptr_t base) {
    std::ostringstream stream;
    stream << "\t0x" << std::hex << base << '\t';
    return stream.str();
}
}

int main(int argc, char** argv) {
    try {
        Check(argc == 2, "expected DLL path");
        Fixture fixture;
        const auto dll = std::filesystem::absolute(argv[1]);
        using NoArgs = DWORD(WINAPI*)();
        using StartAt = DWORD(WINAPI*)(const wchar_t*);
        for (int cycle = 0; cycle < 3; ++cycle) {
            const auto log = fixture.directory / (std::to_wstring(cycle) + L".log");
            {
                Library library(dll);
                const auto start = library.Get<NoArgs>("PhantomDumperStart");
                const auto start_at = library.Get<StartAt>("PhantomDumperStartAt");
                const auto snapshot = library.Get<NoArgs>("PhantomDumperSnapshot");
                const auto stop = library.Get<NoArgs>("PhantomDumperStop");
                Check(!std::filesystem::exists(log), "load alone does not create log");
                Check(snapshot() == 1, "snapshot before initialization");
                Check(start_at(nullptr) == 5 && start_at(L"") == 5, "invalid path arguments");
                Check(start_at(fixture.directory.c_str()) == 2, "I/O failure reported");
                Check(start_at(log.c_str()) == 0, "explicit start with Unicode path");
                Check(start_at(log.c_str()) == 1, "double start rejected");
                const auto first = Read(log);
                Check(first.find("kernel32.dll") != std::string::npos || first.find("KERNEL32.DLL") != std::string::npos,
                    "system module enumerated");
                Check(first.find("PhantomDumper.dll") != std::string::npos, "diagnostic DLL enumerated");
                Check(first.find(RowBase(library.base())) != std::string::npos, "actual DLL base recorded");
                Check(first.find(RowBase(reinterpret_cast<std::uintptr_t>(GetModuleHandleW(nullptr)))) != std::string::npos,
                    "actual host base recorded");
                Check(snapshot() == 0, "snapshot export");
                Check(Read(log).size() > first.size(), "snapshot appended");
                Check(stop() == 0 && stop() == 0, "stop idempotent");
                Check(snapshot() == 1, "snapshot after shutdown");
                Check(start() == 0, "default temp-path start");
                Check(stop() == 0, "stop default session");
            }
            Check(GetModuleHandleW(dll.filename().c_str()) == nullptr, "DLL unloaded after completed calls");
            // Closed log remains removable after unloading.
            Check(std::filesystem::remove(log), "log handle closed");
        }
        const auto default_log = std::filesystem::temp_directory_path() /
            (L"PhantomDumper-" + std::to_wstring(GetCurrentProcessId()) + L".log");
        Check(!Read(default_log).empty(), "default log written");
        std::filesystem::remove(default_log);
        std::cout << "Windows load/start/snapshot/stop/unload checks passed\n";
        return 0;
    } catch (const std::exception& error) {
        std::cerr << error.what() << '\n';
        return 1;
    }
}
