#include "phantom/Api.h"
#include "phantom/Runtime.hpp"
#include <string>
#include <vector>

namespace {
phantom::Runtime& Instance() {
    // Initialized on first exported call, never from DllMain.
    static phantom::Runtime runtime(phantom::EnumerateModules);
    return runtime;
}
template<class Operation> DWORD Guard(Operation operation) noexcept {
    try { return static_cast<DWORD>(operation()); }
    catch (...) { return static_cast<DWORD>(phantom::Status::internal_error); }
}
}

DWORD WINAPI PhantomDumperStart() {
    return Guard([] {
        std::vector<wchar_t> buffer(MAX_PATH + 1);
        const auto size = GetTempPathW(static_cast<DWORD>(buffer.size()), buffer.data());
        if (size == 0) return phantom::Status::log_error;
        if (size >= buffer.size()) {
            buffer.resize(static_cast<std::size_t>(size) + 1);
            const auto retry = GetTempPathW(static_cast<DWORD>(buffer.size()), buffer.data());
            if (retry == 0 || retry >= buffer.size()) return phantom::Status::log_error;
        }
        const auto name = L"PhantomDumper-" + std::to_wstring(GetCurrentProcessId()) + L".log";
        return Instance().Start(std::filesystem::path(buffer.data()) / name);
    });
}
DWORD WINAPI PhantomDumperStartAt(const wchar_t* log_path) {
    if (log_path == nullptr || *log_path == L'\0')
        return static_cast<DWORD>(phantom::Status::invalid_argument);
    return Guard([&] { return Instance().Start(std::filesystem::path(log_path)); });
}
DWORD WINAPI PhantomDumperSnapshot() {
    return Guard([] { return Instance().Snapshot(); });
}
DWORD WINAPI PhantomDumperStop() {
    return Guard([] { return Instance().Stop(); });
}
