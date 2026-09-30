#include "phantom/Runtime.hpp"
#include "phantom/Logger.hpp"
#include <utility>

namespace phantom {
Runtime::Runtime(Provider provider) : provider_(std::move(provider)) {}

Status Runtime::Capture(const std::filesystem::path& path) {
    std::vector<ModuleInfo> modules;
    try { modules = provider_(); }
    catch (...) { return Status::enumeration_error; }
    try { AppendModules(path, modules); }
    catch (...) { return Status::log_error; }
    return Status::ok;
}

Status Runtime::Start(const std::filesystem::path& path) {
    std::lock_guard<std::mutex> lock(mutex_);
    if (started_) return Status::invalid_state;
    if (path.empty()) return Status::invalid_argument;
    // Resolve once before capture so later host working-directory changes cannot
    // redirect subsequent snapshots. Resolution failures remain retryable.
    std::filesystem::path candidate;
    try { candidate = std::filesystem::absolute(path); }
    catch (...) { return Status::log_error; }
    const auto result = Capture(candidate);
    if (result == Status::ok) {
        path_.swap(candidate);
        started_ = true;
    }
    return result;
}

Status Runtime::Snapshot() {
    std::lock_guard<std::mutex> lock(mutex_);
    return started_ ? Capture(path_) : Status::invalid_state;
}

Status Runtime::Stop() {
    std::lock_guard<std::mutex> lock(mutex_);
    started_ = false;
    path_.clear();
    return Status::ok;
}
}
