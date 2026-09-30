#pragma once
#include "ModuleResolver.hpp"
#include <filesystem>
#include <functional>
#include <mutex>

namespace phantom {
enum class Status : unsigned long {
    ok = 0, invalid_state = 1, log_error = 2, enumeration_error = 3,
    internal_error = 4, invalid_argument = 5
};

class Runtime {
public:
    using Provider = std::function<std::vector<ModuleInfo>()>;
    explicit Runtime(Provider provider);
    Status Start(const std::filesystem::path& path);
    Status Snapshot();
    Status Stop();
private:
    Status Capture(const std::filesystem::path& path);
    Provider provider_;
    std::mutex mutex_;
    bool started_ = false;
    std::filesystem::path path_;
};
}
