#include "phantom/ModuleResolver.hpp"
#include <windows.h>
#include <tlhelp32.h>
#include <system_error>

namespace phantom {
namespace {
[[noreturn]] void Fail(DWORD error, const char* operation) {
    throw std::system_error(static_cast<int>(error), std::system_category(), operation);
}
class SnapshotHandle {
public:
    explicit SnapshotHandle(HANDLE handle) : handle_(handle) {}
    ~SnapshotHandle() { CloseHandle(handle_); }
    SnapshotHandle(const SnapshotHandle&) = delete;
    SnapshotHandle& operator=(const SnapshotHandle&) = delete;
    HANDLE get() const { return handle_; }
private:
    HANDLE handle_;
};
std::string Utf8(const wchar_t* value) {
    const int size = WideCharToMultiByte(CP_UTF8, WC_ERR_INVALID_CHARS, value, -1, nullptr, 0, nullptr, nullptr);
    if (size == 0) Fail(GetLastError(), "WideCharToMultiByte(size)");
    std::string result(static_cast<std::size_t>(size), '\0');
    if (WideCharToMultiByte(CP_UTF8, WC_ERR_INVALID_CHARS, value, -1, result.data(), size, nullptr, nullptr) == 0)
        Fail(GetLastError(), "WideCharToMultiByte");
    result.pop_back();
    return result;
}
}

std::vector<ModuleInfo> EnumerateModules() {
    HANDLE raw = INVALID_HANDLE_VALUE;
    // Loader churn can cause ERROR_BAD_LENGTH. Bound retries to avoid hangs.
    for (int attempt = 0; attempt < 8; ++attempt) {
        raw = CreateToolhelp32Snapshot(TH32CS_SNAPMODULE, GetCurrentProcessId());
        if (raw != INVALID_HANDLE_VALUE) break;
        const auto error = GetLastError();
        if (error != ERROR_BAD_LENGTH || attempt == 7) Fail(error, "CreateToolhelp32Snapshot");
    }
    SnapshotHandle snapshot(raw);
    MODULEENTRY32W entry{};
    entry.dwSize = sizeof(entry);
    if (!Module32FirstW(snapshot.get(), &entry)) Fail(GetLastError(), "Module32FirstW");
    std::vector<ModuleInfo> modules;
    for (;;) {
        entry.szModule[MAX_MODULE_NAME32] = L'\0';
        entry.szExePath[MAX_PATH - 1] = L'\0';
        modules.push_back({Utf8(entry.szModule), Utf8(entry.szExePath),
            reinterpret_cast<std::uintptr_t>(entry.modBaseAddr), entry.modBaseSize});
        if (!Module32NextW(snapshot.get(), &entry)) {
            const auto error = GetLastError();
            if (error != ERROR_NO_MORE_FILES) Fail(error, "Module32NextW");
            break;
        }
    }
    return modules;
}
}
