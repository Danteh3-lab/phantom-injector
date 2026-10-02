#include "phantom/ExportManager.hpp"
#include "phantom/PatternScanner.hpp"
#include <algorithm>
#include <array>
#include <cstring>
#include <iostream>
#include <stdexcept>
#include <type_traits>
#ifdef _WIN32
#include <windows.h>
#endif

namespace {
void Check(bool condition, const char* message) {
    if (!condition) throw std::runtime_error(message);
}
struct DevPlayer {
    std::uint32_t marker;
    std::int32_t health;
    float x, y, z;
    std::int64_t counter;
    std::uint64_t ticks;
    double score;
    std::uint64_t next;
};
static_assert(std::is_standard_layout_v<DevPlayer>);
alignas(DevPlayer) std::array<std::byte, sizeof(DevPlayer)> storage{};
template<class T> void Put(std::size_t offset, T value) {
    Check(offset <= storage.size() && sizeof(value) <= storage.size() - offset, "fixture write bounds");
    std::memcpy(storage.data() + offset, &value, sizeof(value));
}
#ifndef _WIN32
// Portable CI has no Windows memory API: only this owned fixture is accessible.
class Buffer final : public phantom::MemoryBackend {
public:
    phantom::MemoryRegion Query(std::uintptr_t address) const override {
        const auto base = reinterpret_cast<std::uintptr_t>(storage.data());
        Check(address >= base && address - base < storage.size(), "fixture query bounds");
        return {base, base, storage.size(), 0x1000, 0x04, 0x20000};
    }
    phantom::MemoryCopyResult Copy(std::uintptr_t address, std::byte* output, std::size_t size) const override {
        const auto base = reinterpret_cast<std::uintptr_t>(storage.data());
        Check(address >= base && address - base <= storage.size() && size <= storage.size() - (address - base), "fixture copy bounds");
        std::memcpy(output, storage.data() + (address - base), size);
        return {size, 0};
    }
};
#endif
}
int main(int argc, char** argv) {
    try {
        Check(argc == 2, "expected caller-owned output directory");
        const auto directory = std::filesystem::absolute(argv[1]);
        std::filesystem::create_directories(directory);
        const auto base = reinterpret_cast<std::uintptr_t>(storage.data());
        // A known byte signature, independent of native integer byte order.
        storage[0] = std::byte{0x50}; storage[1] = std::byte{0x44};
        storage[2] = std::byte{0x4d}; storage[3] = std::byte{0x50};
        Put<std::int32_t>(offsetof(DevPlayer, health), 123);
        Put<float>(offsetof(DevPlayer, x), 2.5f);
        Put<std::int64_t>(offsetof(DevPlayer, counter), -123456);
        Put<std::uint64_t>(offsetof(DevPlayer, ticks), 123456);
        Put<double>(offsetof(DevPlayer, score), 3.125);
        Put<std::uint64_t>(offsetof(DevPlayer, next), 0);
#ifdef _WIN32
        phantom::MemoryInspector memory;
        const auto modules = phantom::EnumerateModules();
        const auto found = std::find_if(modules.begin(), modules.end(), [base](const auto& module) {
            return base >= module.base && base - module.base < module.image_size &&
                storage.size() <= module.image_size - (base - module.base);
        });
        Check(found != modules.end(), "owned fixture lies in loaded host module");
        const auto module = *found;
#else
        const Buffer backend;
        phantom::MemoryInspector memory(backend);
        const phantom::ModuleInfo module{"Fixture.exe", "", base, static_cast<std::uint32_t>(storage.size())};
#endif
        phantom::PatternScanner scanner(memory);
        phantom::ScanOptions options;
        options.chunk_size = 3;
        const auto scan = scanner.Scan(base, storage.size(), phantom::Pattern::Parse("50 44 ?? 50"), options);
        Check(scan.status == phantom::ScanStatus::ok && scan.matches == std::vector<std::uintptr_t>{base}, "known signature located through memory inspector");
        const phantom::StructureLayout layout("DevPlayer", sizeof(DevPlayer), {
            {"health", offsetof(DevPlayer, health), phantom::FieldType::int32},
            {"x", offsetof(DevPlayer, x), phantom::FieldType::float32},
            {"next", offsetof(DevPlayer, next), phantom::FieldType::pointer64},
            {"marker", offsetof(DevPlayer, marker), phantom::FieldType::uint32},
            {"counter", offsetof(DevPlayer, counter), phantom::FieldType::int64},
            {"ticks", offsetof(DevPlayer, ticks), phantom::FieldType::uint64},
            {"score", offsetof(DevPlayer, score), phantom::FieldType::float64}});
        phantom::StructureInspector structures(memory);
        const auto inspected = structures.Inspect(scan.matches[0], layout);
        Check(inspected.status == phantom::StructureStatus::ok && std::get<std::int32_t>(inspected.fields[0].value) == 123 &&
            std::get<float>(inspected.fields[1].value) == 2.5f && std::get<phantom::PointerValue>(inspected.fields[2].value).address == 0,
            "known fields decoded from located structure");
        phantom::OffsetManager catalog({"dev-\xe6\xb5\x8b\xe8\xaf\x95", "fixture-build-1"});
        catalog.AddModuleAddress("z.marker", module, scan.matches[0], 4, "fixture-image-1");
        catalog.AddField("b.next", layout, "next");
        catalog.AddField("a.health", layout, "health");
        catalog.AddField("c.marker", layout, "marker");
        catalog.AddField("d.x", layout, "x");
        catalog.AddField("e.counter", layout, "counter");
        catalog.AddField("f.ticks", layout, "ticks");
        catalog.AddField("g.score", layout, "score");
        const auto rebased = catalog.ResolveField("a.health", base, layout, catalog.version());
        Check(rebased.status == phantom::OffsetStatus::ok && rebased.address == inspected.fields[0].address, "catalog resolves known field address");
        constexpr char capture[] = "capture\"\\\n\t\xc3\xa9\0tail";
        const phantom::ExportMetadata metadata{std::string(capture, sizeof(capture) - 1), "2026-01-01T00:00:00Z"};
        phantom::ExportManager::WriteJson(directory / "fixture.json", catalog, metadata);
        phantom::ExportManager::WriteCppHeader(directory / "fixture.hpp", catalog, metadata);
        const phantom::OffsetManager empty({"empty-game", "build-0"});
        phantom::ExportManager::WriteJson(directory / "empty.json", empty);
        phantom::ExportManager::WriteCppHeader(directory / "empty.hpp", empty);
        std::cout << "Memory/pattern/structure/offset/export workflow passed\n";
        return 0;
    } catch (const std::exception& error) { std::cerr << error.what() << '\n'; return 1; }
}
