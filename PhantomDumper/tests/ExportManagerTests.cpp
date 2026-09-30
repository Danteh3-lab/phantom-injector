#include "phantom/ExportManager.hpp"
#include <chrono>
#include <fstream>
#include <iostream>
#include <iterator>
#include <locale>
#include <stdexcept>

namespace {
void Check(bool condition, const char* message) {
    if (!condition) throw std::runtime_error(message);
}
template<class Function> void Reject(Function function) {
    try { function(); }
    catch (const std::invalid_argument&) { return; }
    throw std::runtime_error("invalid export text accepted");
}
template<class Function> void IoFailure(Function function) {
    try { function(); }
    catch (const std::ios_base::failure&) { return; }
    throw std::runtime_error("export I/O failure not reported");
}
struct Fixture {
    std::filesystem::path directory = std::filesystem::temp_directory_path() /
        ("phantom-export-" + std::to_string(std::chrono::steady_clock::now().time_since_epoch().count()));
    Fixture() { Check(std::filesystem::create_directory(directory), "create export fixture directory"); }
    ~Fixture() { std::error_code error; std::filesystem::remove_all(directory, error); }
};
std::string Read(const std::filesystem::path& path) {
    std::ifstream file(path, std::ios::binary);
    Check(file.good(), "read export output");
    return {std::istreambuf_iterator<char>(file), std::istreambuf_iterator<char>()};
}
struct LocaleGuard {
    std::locale original = std::locale();
    ~LocaleGuard() { std::locale::global(original); }
};
struct Grouping : std::numpunct<char> {
    char do_thousands_sep() const override { return ','; }
    std::string do_grouping() const override { return "\3"; }
};
}
int main() {
    try {
        using phantom::ExportManager;
        const phantom::ModuleInfo module{"Game\"\\\n.exe", "ignored", 0x123456780000ULL, 100000};
        const phantom::StructureLayout layout("Player\t", 24, {{"health\r", 0, phantom::FieldType::int32},
            {"next", 16, phantom::FieldType::pointer64}});
        const phantom::VersionInfo version{"game-\xe6\xb5\x8b\xe8\xaf\x95", "build\"\\\n"};
        phantom::OffsetManager first(version), second(version);
        first.AddModuleAddress("z", module, module.base + 4096, 8, "image-1");
        first.AddModuleAddress("a", module, module.base, 1, "image-1");
        first.AddField("z.field", layout, "next"); first.AddField("a.field", layout, "health\r");
        second.AddField("a.field", layout, "health\r"); second.AddField("z.field", layout, "next");
        second.AddModuleAddress("a", module, module.base, 1, "image-1");
        second.AddModuleAddress("z", module, module.base + 4096, 8, "image-1");
        constexpr char capture[] = "capture\"\\\n\t\0tail";
        const phantom::ExportMetadata metadata{std::string(capture, sizeof(capture) - 1), "2026-01-01T00:00:00Z"};
        const auto json = ExportManager::Json(first, metadata);
        const auto header = ExportManager::CppHeader(first, metadata);
        Check(json == ExportManager::Json(second, metadata) && header == ExportManager::CppHeader(second, metadata),
            "insertion order does not affect export bytes");
        Check(json.find("\"rva\": 4096") != std::string::npos && json.find("\"image_size\": 100000") != std::string::npos &&
            json.find("\"type\": \"pointer64\"") != std::string::npos, "JSON numeric/type metadata retained");
        Check(json.find("\\u0000") != std::string::npos && json.find("\\u000a") != std::string::npos &&
            json.find("\\u000d") != std::string::npos && json.find("\\\"") != std::string::npos, "JSON controls, quote and NUL escaped");
        Check(json.find("base") == std::string::npos && json.find("path") == std::string::npos, "catalog export has no captured base/path");
        Check(header.find("FieldKind::pointer64") != std::string::npos && header.find("\\000") != std::string::npos &&
            header.find("std::array<ModuleOffsetRecord, 2>") != std::string::npos, "header typed records and NUL-safe literal emitted");
        for (const unsigned char byte : header) Check(byte < 0x80, "generated header is ASCII regardless of input UTF-8");
        {
            LocaleGuard guard;
            std::locale::global(std::locale(std::locale::classic(), new Grouping));
            Check(ExportManager::Json(first, metadata) == json && ExportManager::CppHeader(first, metadata) == header,
                "numeric output ignores global locale");
        }
        phantom::OffsetManager empty({"empty", "build-0"});
        Check(ExportManager::Json(empty).find("\"modules\": []") != std::string::npos &&
            ExportManager::CppHeader(empty).find("std::array<FieldOffsetRecord, 0>") != std::string::npos, "empty catalogs supported");

        for (const auto& invalid : {std::string("\xc0\xaf", 2), std::string("\xe0\x80\xaf", 3), std::string("\xed\xa0\x80", 3),
            std::string("\xf4\x90\x80\x80", 4), std::string("\xf5\x80\x80\x80", 4), std::string("\xc2", 1),
            std::string("\x80", 1), std::string("\xc2X", 2)}) {
            const phantom::ExportMetadata bad{invalid, ""};
            Reject([&] { (void)ExportManager::Json(first, bad); });
            Reject([&] { (void)ExportManager::CppHeader(first, bad); });
        }
        for (const auto& valid : {std::string("\xc2\x80", 2), std::string("\xe0\xa0\x80", 3), std::string("\xed\x9f\xbf", 3),
            std::string("\xf0\x90\x80\x80", 4), std::string("\xf4\x8f\xbf\xbf", 4)})
            Check(!ExportManager::Json(first, {valid, ""}).empty() && !ExportManager::CppHeader(first, {valid, ""}).empty(),
                "valid UTF-8 boundary scalar values accepted");
        Reject([&] { (void)ExportManager::Json(first, {std::string(257, 'x'), ""}); });
        Reject([&] { (void)ExportManager::CppHeader(first, {"", std::string(257, 'x')}); });
        phantom::OffsetManager invalid_catalog({std::string("\xff", 1), "build"});
        Reject([&] { (void)ExportManager::Json(invalid_catalog); });
        Reject([&] { (void)ExportManager::CppHeader(invalid_catalog); });
        phantom::OffsetManager invalid_record({"game", "build"});
        invalid_record.AddModuleAddress(std::string("\x80", 1), module, module.base, 1, "image-1");
        Reject([&] { (void)ExportManager::Json(invalid_record); });

        Fixture fixture;
        // Filesystem-native Unicode path is verified on Windows as well as POSIX.
#ifdef _WIN32
        const auto json_path = fixture.directory / std::filesystem::path(L"\u6d4b\u8bd5.json");
#else
        // Avoid locale-dependent wide-to-native conversion on POSIX.
        const auto json_path = fixture.directory / std::filesystem::u8path("\xe6\xb5\x8b\xe8\xaf\x95.json");
#endif
        const auto header_path = fixture.directory / "offsets.hpp";
        ExportManager::WriteJson(json_path, first, metadata);
        ExportManager::WriteCppHeader(header_path, first, metadata);
        Check(Read(json_path) == json && Read(header_path) == header, "file bytes equal in-memory renderings");
        ExportManager::WriteJson(json_path, empty);
        Check(Read(json_path) == ExportManager::Json(empty), "explicit destination overwrites/truncates old output");
        const auto previous = Read(json_path);
        Reject([&] { ExportManager::WriteJson(json_path, first, {std::string("\xff", 1), ""}); });
        Reject([&] { ExportManager::WriteCppHeader(header_path, first, {std::string(257, 'x'), ""}); });
        Check(Read(json_path) == previous && Read(header_path) == header, "invalid serialization leaves existing destinations intact");
        IoFailure([&] { ExportManager::WriteJson(fixture.directory, first); });
        IoFailure([&] { ExportManager::WriteCppHeader(fixture.directory / "missing" / "offsets.hpp", first); });
        Check(!std::filesystem::exists(fixture.directory / "missing"), "export does not create parents");
        Check(std::filesystem::remove(json_path) && std::filesystem::remove(header_path), "files closed on successful return");
        std::cout << "ExportManager checks passed\n";
        return 0;
    } catch (const std::exception& error) { std::cerr << error.what() << '\n'; return 1; }
}
