#pragma once
#include "phantom/ModuleResolver.hpp"
#include "phantom/StructureInspector.hpp"
#include <string_view>

namespace phantom {
struct VersionInfo {
    std::string game;
    std::string build_id; // Host-supplied game version/fingerprint; not auto-detected.
};
struct ModuleOffset {
    std::string name; // Unique catalog key.
    std::string module_name;
    std::string module_build_id;
    std::uint32_t image_size;
    std::uint32_t rva; // Relative to image base; never an absolute address or disk file offset.
    std::size_t width;
};
struct FieldOffset {
    std::string name; // Unique catalog key.
    std::string structure_name;
    std::size_t structure_size;
    FieldDefinition field; // Structure-relative offset/type, independent of module RVAs.
};
enum class OffsetStatus { ok, not_found, version_mismatch, module_mismatch, layout_mismatch, invalid_range };
struct OffsetResult {
    OffsetStatus status = OffsetStatus::ok;
    std::uintptr_t address = 0; // Set only on success; no readability/lifetime guarantee.
};

class OffsetManager {
public:
    static constexpr std::size_t max_records = 4096; // Combined module and field records.
    // Each catalog belongs to one immutable game/build identity.
    // All text identifiers must be nonempty, NUL-free and <=128 bytes.
    explicit OffsetManager(VersionInfo version);
    const VersionInfo& version() const noexcept { return version_; }
    const std::vector<ModuleOffset>& module_offsets() const noexcept { return modules_; }
    const std::vector<FieldOffset>& field_offsets() const noexcept { return fields_; }
    // Invalid/duplicate records throw invalid_argument; a full catalog throws length_error.
    // Successful insertion stores metadata only and does not inspect source memory.
    void AddModuleAddress(std::string name, const ModuleInfo& module, std::uintptr_t address,
        std::size_t width, std::string module_build_id);
    void AddField(std::string name, const StructureLayout& layout, std::string_view field_name);
    OffsetResult ResolveModule(std::string_view name, const ModuleInfo& current,
        const VersionInfo& current_version, std::string_view current_module_build_id) const;
    OffsetResult ResolveField(std::string_view name, std::uintptr_t structure_base,
        const StructureLayout& current, const VersionInfo& current_version) const;
private:
    void CheckInsert(std::string_view name) const;
    const VersionInfo version_;
    std::vector<ModuleOffset> modules_;
    std::vector<FieldOffset> fields_;
};
}
