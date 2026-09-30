#include "phantom/Logger.hpp"
#include "phantom/Runtime.hpp"
#include <atomic>
#include <chrono>
#include <fstream>
#include <iostream>
#include <iterator>
#include <locale>
#include <stdexcept>
#include <thread>

namespace {
void Check(bool condition, const char* message) {
    if (!condition) throw std::runtime_error(message);
}
struct Fixture {
    std::filesystem::path directory = std::filesystem::temp_directory_path() /
        ("phantom-core-" + std::to_string(std::chrono::steady_clock::now().time_since_epoch().count()));
    Fixture() { Check(std::filesystem::create_directory(directory), "create fixture directory"); }
    ~Fixture() { std::error_code error; std::filesystem::remove_all(directory, error); }
};
struct CurrentPathGuard {
    std::filesystem::path original = std::filesystem::current_path();
    ~CurrentPathGuard() { std::error_code error; std::filesystem::current_path(original, error); }
};
struct GlobalLocaleGuard {
    std::locale original = std::locale();
    ~GlobalLocaleGuard() { std::locale::global(original); }
};
struct GroupingPunct : std::numpunct<char> {
    char do_thousands_sep() const override { return ','; }
    std::string do_grouping() const override { return "\3"; }
};
std::string Read(const std::filesystem::path& path) {
    std::ifstream file(path, std::ios::binary);
    Check(file.good(), "read log");
    return {std::istreambuf_iterator<char>(file), std::istreambuf_iterator<char>()};
}
}

int main() {
    try {
        Fixture fixture;
        const std::vector<phantom::ModuleInfo> modules = {
            {"game.exe", "C:\\game\\game.exe", 0x7ff600001000ULL, 0x12000},
            {"tab\tline\n", "x\r\nforged", 0x1000, 0x20}
        };
        const auto formatted = phantom::FormatModules(modules);
        Check(formatted.find("game.exe\t0x7ff600001000\t0x12000\tC:\\\\game\\\\game.exe\n") != std::string::npos,
            "64-bit addresses and image sizes retained");
        Check(formatted.find("tab\\tline\\n\t0x1000\t0x20\tx\\r\\nforged\n") != std::string::npos,
            "log fields cannot inject rows");
        Check(phantom::FormatModules({}).find("modules=0\n") != std::string::npos, "empty snapshot formatting");

        {
            GlobalLocaleGuard locale_guard;
            std::locale::global(std::locale(std::locale::classic(), new GroupingPunct));
            std::vector<phantom::ModuleInfo> many(1000, {"module", "path", 0x123456789abcULL, 0x123456});
            const auto locale_formatted = phantom::FormatModules(many);
            Check(locale_formatted.find("modules=1000\n") != std::string::npos,
                "module count ignores global grouping locale");
            Check(locale_formatted.find("0x123456789abc\t0x123456\t") != std::string::npos,
                "hex addresses and sizes ignore global grouping locale");
        }

        using phantom::Status;
        std::atomic<int> calls{0};
        std::atomic<bool> fail_enumeration{true};
        phantom::Runtime runtime([&] {
            ++calls;
            if (fail_enumeration) throw std::runtime_error("synthetic enumeration failure");
            return modules;
        });
        const auto log = fixture.directory / "modules.log";
        Check(runtime.Snapshot() == Status::invalid_state, "snapshot before start");
        Check(runtime.Stop() == Status::ok && runtime.Stop() == Status::ok, "stop is idempotent");
        Check(runtime.Start({}) == Status::invalid_argument, "empty path rejected");
        Check(calls == 0, "invalid operations do not enumerate");
        Check(runtime.Start(log) == Status::enumeration_error, "enumeration failure classified");
        Check(!std::filesystem::exists(log), "failed enumeration does not create a log");
        fail_enumeration = false;
        Check(runtime.Start(fixture.directory) == Status::log_error, "directory rejected as log");
        Check(runtime.Start(fixture.directory / "missing" / "modules.log") == Status::log_error, "missing parent rejected");
        Check(runtime.Start(log) == Status::ok, "start retries after failures");
        const int after_start = calls;
        Check(runtime.Start(log) == Status::invalid_state && calls == after_start, "double start has no side effects");
        Check(Read(log) == formatted, "initial snapshot written");
        fail_enumeration = true;
        Check(runtime.Snapshot() == Status::enumeration_error, "refresh failure classified");
        Check(Read(log) == formatted, "refresh enumeration failure preserves log");
        fail_enumeration = false;
        Check(runtime.Snapshot() == Status::ok, "refresh retries without restart");
        Check(Read(log) == formatted + formatted, "refresh appends instead of truncating");

        std::atomic<int> failures{0};
        std::vector<std::thread> workers;
        for (int i = 0; i < 4; ++i) workers.emplace_back([&] {
            for (int j = 0; j < 10; ++j) if (runtime.Snapshot() != Status::ok) ++failures;
        });
        for (auto& worker : workers) worker.join();
        Check(failures == 0, "concurrent snapshots succeed");
        std::string expected;
        for (int i = 0; i < 42; ++i) expected += formatted;
        Check(Read(log) == expected, "snapshots serialized without interleaved log rows");

        // No persistent file handle: replace the log with a directory while started.
        std::filesystem::remove(log);
        std::filesystem::create_directory(log);
        Check(runtime.Snapshot() == Status::log_error, "refresh I/O failure classified");
        std::filesystem::remove(log);
        Check(runtime.Snapshot() == Status::ok, "refresh retries after I/O recovery");
        Check(runtime.Stop() == Status::ok, "stop after refresh");
        Check(runtime.Snapshot() == Status::invalid_state, "snapshot after stop");
        const auto directory_a = fixture.directory / "a";
        const auto directory_b = fixture.directory / "b";
        std::filesystem::create_directory(directory_a);
        std::filesystem::create_directory(directory_b);
        {
            CurrentPathGuard cwd_guard;
            std::filesystem::current_path(directory_a);
            phantom::Runtime relative_runtime([&] { return modules; });
            Check(relative_runtime.Start("relative.log") == Status::ok, "start resolves relative destination");
            std::filesystem::current_path(directory_b);
            Check(relative_runtime.Snapshot() == Status::ok, "snapshot survives host working-directory change");
            Check(relative_runtime.Stop() == Status::ok, "stop relative destination runtime");
        }
        Check(Read(directory_a / "relative.log") == formatted + formatted,
            "relative destination remains anchored to start directory");
        Check(!std::filesystem::exists(directory_b / "relative.log"), "working-directory change does not redirect log");

        const auto next_log = fixture.directory / "next.log";
        Check(runtime.Start(next_log) == Status::ok, "restart at new path");
        Check(Read(next_log) == formatted, "restart uses new destination");
        Check(runtime.Stop() == Status::ok, "final stop");
        std::cout << "PhantomDumper core checks passed\n";
        return 0;
    } catch (const std::exception& error) {
        std::cerr << error.what() << '\n';
        return 1;
    }
}
