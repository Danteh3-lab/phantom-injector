#include "phantom/OffsetManager.hpp"
#include <iostream>
#include <limits>
#include <stdexcept>
#include <utility>

namespace {
void Check(bool condition, const char* message) {
    if (!condition) throw std::runtime_error(message);
}
template<class Function> void Reject(Function function) {
    try { function(); }
    catch (const std::invalid_argument&) { return; }
    throw std::runtime_error("invalid offset metadata accepted");
}
}
int main() {
    try {
        using phantom::FieldType;
        using phantom::OffsetStatus;
        using phantom::StructureLayout;
        const phantom::VersionInfo version{"dev-game", "build-42"};
        Reject([] { phantom::OffsetManager invalid({"", "build"}); });
        Reject([] { phantom::OffsetManager invalid({"game", ""}); });
        Reject([] { phantom::OffsetManager invalid({std::string(129, 'x'), "build"}); });
        Reject([] { phantom::OffsetManager invalid({"game", std::string("x\0y", 3)}); });
        phantom::OffsetManager manager(version);
        const phantom::ModuleInfo module{"Game.exe", "C:/dev/Game.exe", 0x123456780000ULL, 0x1000};
        const StructureLayout player("Player", 24, {{"health", 0, FieldType::int32}, {"x", 4, FieldType::float32},
            {"next", 16, FieldType::pointer64}});
        manager.AddModuleAddress("registry", module, module.base + 0xabc, 8, "image-123");
        manager.AddModuleAddress("image_start", module, module.base, 1, "image-123");
        manager.AddModuleAddress("image_last", module, module.base + module.image_size - 1, 1, "image-123");
        manager.AddModuleAddress("full_image", module, module.base, module.image_size, "image-123");
        manager.AddField("player.health", player, "health");
        manager.AddField("player.next", player, "next");
        Check(manager.version().game == version.game && manager.version().build_id == version.build_id &&
            manager.module_offsets()[0].rva == 0xabc && manager.module_offsets()[0].width == 8 &&
            manager.module_offsets()[0].module_build_id == "image-123", "catalog retains version, width and RVA rather than absolute address");
        Check(manager.field_offsets()[0].field.offset == 0 && manager.field_offsets()[1].field.offset == 16 &&
            manager.field_offsets()[1].field.type == FieldType::pointer64 && manager.field_offsets()[1].structure_size == 24,
            "field offsets retain type/layout metadata and allow zero");

        auto current = module;
        current.base = 0x234567890000ULL;
        current.path = "D:/relocated/Game.exe";
        const auto rebased = manager.ResolveModule("registry", current, version, "image-123");
        Check(rebased.status == OffsetStatus::ok && rebased.address == current.base + 0xabc, "ASLR rebasing preserves RVA and permits path relocation");
        Check(manager.ResolveModule("image_start", current, version, "image-123").address == current.base &&
            manager.ResolveModule("image_last", current, version, "image-123").address == current.base + current.image_size - 1,
            "first and last image byte resolve");
        const auto field = manager.ResolveField("player.next", current.base, player, version);
        Check(field.status == OffsetStatus::ok && field.address == current.base + 16 &&
            manager.ResolveField("player.health", current.base, player, version).address == current.base, "structure rebasing uses field offset, not module RVA");
        Check(manager.ResolveField("registry", current.base, player, version).status == OffsetStatus::not_found &&
            manager.ResolveModule("player.health", current, version, "image-123").status == OffsetStatus::not_found,
            "module and structure lookup namespaces remain typed");
        Check(manager.ResolveModule("missing", current, version, "image-123").status == OffsetStatus::not_found, "unknown key rejected");
        const phantom::VersionInfo wrong_build{"dev-game", "build-43"};
        const phantom::VersionInfo wrong_game{"another-game", "build-42"};
        Check(manager.ResolveModule("registry", current, wrong_build, "image-123").status == OffsetStatus::version_mismatch &&
            manager.ResolveField("player.health", current.base, player, wrong_game).status == OffsetStatus::version_mismatch,
            "game/build identities reject cross-version resolution");
        Check(manager.ResolveModule("registry", current, version, "image-124").status == OffsetStatus::module_mismatch, "image build mismatch rejected");
        current.name = "Other.exe";
        Check(manager.ResolveModule("registry", current, version, "image-123").status == OffsetStatus::module_mismatch, "module name mismatch rejected");
        current = module; current.image_size += 1;
        Check(manager.ResolveModule("registry", current, version, "image-123").status == OffsetStatus::module_mismatch, "image size mismatch rejected");
        current = module; current.base = 0;
        Check(manager.ResolveModule("registry", current, version, "image-123").status == OffsetStatus::invalid_range, "null module base rejected");
        const auto maximum = std::numeric_limits<std::uintptr_t>::max();
        current.base = maximum - module.image_size + 1;
        const auto overflow = manager.ResolveModule("registry", current, version, "image-123");
        Check(overflow.status == OffsetStatus::invalid_range && overflow.address == 0, "module interval overflow returns no address");
        current.base = maximum - module.image_size;
        Check(manager.ResolveModule("image_last", current, version, "image-123").address == maximum - 1, "highest representable exclusive interval accepted");

        const StructureLayout renamed("Other", 24, player.fields());
        const StructureLayout resized("Player", 32, player.fields());
        const StructureLayout moved_field("Player", 24, {{"health", 4, FieldType::int32}});
        const StructureLayout changed_type("Player", 24, {{"health", 0, FieldType::uint32}});
        const StructureLayout absent("Player", 24, {{"other", 0, FieldType::int32}});
        for (const auto* changed : {&renamed, &resized, &moved_field, &changed_type, &absent})
            Check(manager.ResolveField("player.health", module.base, *changed, version).status == OffsetStatus::layout_mismatch,
                "name, size, offset, type and missing-field mismatches rejected");
        Check(manager.ResolveField("player.next", 0, player, version).status == OffsetStatus::invalid_range &&
            manager.ResolveField("player.next", maximum - 10, player, version).status == OffsetStatus::invalid_range,
            "structure base null/overflow rejected");
        Check(manager.ResolveField("player.next", maximum - 24, player, version).address == maximum - 8, "structure field end bound checked");

        const auto count = manager.module_offsets().size();
        Reject([&] { manager.AddModuleAddress("registry", module, module.base, 1, "image-123"); });
        Reject([&] { manager.AddModuleAddress("player.health", module, module.base, 1, "image-123"); });
        Reject([&] { manager.AddField("registry", player, "health"); });
        Reject([&] { manager.AddField("missing", player, "missing"); });
        Reject([&] { manager.AddField("", player, "health"); });
        Reject([&] { manager.AddModuleAddress(std::string("x\0y", 3), module, module.base, 1, "image-123"); });
        Reject([&] { manager.AddModuleAddress("too_long", module, module.base, 1, std::string(129, 'x')); });
        Reject([&] { manager.AddModuleAddress("no_image_build", module, module.base, 1, ""); });
        Reject([&] { manager.AddModuleAddress("zero_width", module, module.base, 0, "image-123"); });
        Reject([&] { manager.AddModuleAddress("before", module, module.base - 1, 1, "image-123"); });
        Reject([&] { manager.AddModuleAddress("end", module, module.base + module.image_size, 1, "image-123"); });
        Reject([&] { manager.AddModuleAddress("cross_end", module, module.base + module.image_size - 1, 2, "image-123"); });
        Reject([&] { manager.AddModuleAddress("width_overflow", module, module.base, std::numeric_limits<std::size_t>::max(), "image-123"); });
        auto invalid = module; invalid.base = 0;
        Reject([&] { manager.AddModuleAddress("null_module", invalid, 1, 1, "image-123"); });
        invalid = module; invalid.image_size = 0;
        Reject([&] { manager.AddModuleAddress("empty_module", invalid, invalid.base, 1, "image-123"); });
        invalid = module; invalid.base = maximum - 1;
        Reject([&] { manager.AddModuleAddress("overflow_module", invalid, invalid.base, 1, "image-123"); });
        invalid = module; invalid.name = "";
        Reject([&] { manager.AddModuleAddress("unnamed_module", invalid, invalid.base, 1, "image-123"); });
        Check(manager.module_offsets().size() == count && manager.field_offsets().size() == 2, "invalid insertions leave catalog intact");
        const auto copied = manager;
        Check(copied.ResolveModule("registry", module, version, "image-123").address == module.base + 0xabc &&
            copied.module_offsets()[0].rva == manager.module_offsets()[0].rva, "catalog copy retains identity and records");

        phantom::OffsetManager bounded(version);
        // Cap counts both kinds of record, with no silent overwrite/eviction.
        bounded.AddField("health", player, "health");
        for (std::size_t i = 1; i < phantom::OffsetManager::max_records; ++i)
            bounded.AddModuleAddress("alias" + std::to_string(i), module, module.base, 1, "image-123");
        bool capped = false;
        try { bounded.AddField("extra", player, "next"); }
        catch (const std::length_error&) { capped = true; }
        Check(capped && bounded.module_offsets().size() + bounded.field_offsets().size() == phantom::OffsetManager::max_records,
            "combined record cap preserves existing records");
        std::cout << "OffsetManager checks passed\n";
        return 0;
    } catch (const std::exception& error) { std::cerr << error.what() << '\n'; return 1; }
}
