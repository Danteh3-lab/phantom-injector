#include "phantom/OffsetManager.hpp"
#include <algorithm>
#include <limits>
#include <stdexcept>
#include <utility>

namespace phantom {
namespace {
bool TextValid(std::string_view text) {
    return !text.empty() && text.size() <= 128 && text.find('\0') == std::string_view::npos;
}
bool RangeValid(std::uintptr_t base, std::size_t size) {
    return base != 0 && size != 0 && size <= std::numeric_limits<std::uintptr_t>::max() - base;
}
bool SameVersion(const VersionInfo& left, const VersionInfo& right) {
    return left.game == right.game && left.build_id == right.build_id;
}
}

OffsetManager::OffsetManager(VersionInfo version) : version_(std::move(version)) {
    if (!TextValid(version_.game) || !TextValid(version_.build_id))
        throw std::invalid_argument("invalid game/build identity");
}
void OffsetManager::CheckInsert(std::string_view name) const {
    if (!TextValid(name)) throw std::invalid_argument("invalid offset record name");
    const auto named = [name](const auto& record) { return record.name == name; };
    if (std::any_of(modules_.begin(), modules_.end(), named) || std::any_of(fields_.begin(), fields_.end(), named))
        throw std::invalid_argument("duplicate offset record name");
    if (modules_.size() + fields_.size() == max_records) throw std::length_error("offset catalog is full");
}
void OffsetManager::AddModuleAddress(std::string name, const ModuleInfo& module, std::uintptr_t address,
    std::size_t width, std::string module_build_id) {
    if (!TextValid(module.name) || !TextValid(module_build_id) || !RangeValid(module.base, module.image_size) ||
        width == 0 || address < module.base || address - module.base >= module.image_size ||
        width > module.image_size - (address - module.base))
        throw std::invalid_argument("invalid module identity/address/span");
    CheckInsert(name);
    modules_.push_back({std::move(name), module.name, std::move(module_build_id), module.image_size,
        static_cast<std::uint32_t>(address - module.base), width});
}
void OffsetManager::AddField(std::string name, const StructureLayout& layout, std::string_view field_name) {
    const auto& definitions = layout.fields();
    const auto field = std::find_if(definitions.begin(), definitions.end(), [field_name](const auto& item) {
        return item.name == field_name;
    });
    if (field == definitions.end()) throw std::invalid_argument("field is not in supplied layout");
    CheckInsert(name);
    fields_.push_back({std::move(name), layout.name(), layout.size(), *field});
}
OffsetResult OffsetManager::ResolveModule(std::string_view name, const ModuleInfo& current,
    const VersionInfo& current_version, std::string_view current_module_build_id) const {
    const auto record = std::find_if(modules_.begin(), modules_.end(), [name](const auto& item) { return item.name == name; });
    if (record == modules_.end()) return {OffsetStatus::not_found, 0};
    if (!SameVersion(version_, current_version)) return {OffsetStatus::version_mismatch, 0};
    if (record->module_name != current.name || record->module_build_id != current_module_build_id || record->image_size != current.image_size)
        return {OffsetStatus::module_mismatch, 0};
    if (!RangeValid(current.base, current.image_size)) return {OffsetStatus::invalid_range, 0};
    return {OffsetStatus::ok, current.base + record->rva};
}
OffsetResult OffsetManager::ResolveField(std::string_view name, std::uintptr_t structure_base,
    const StructureLayout& current, const VersionInfo& current_version) const {
    const auto record = std::find_if(fields_.begin(), fields_.end(), [name](const auto& item) { return item.name == name; });
    if (record == fields_.end()) return {OffsetStatus::not_found, 0};
    if (!SameVersion(version_, current_version)) return {OffsetStatus::version_mismatch, 0};
    const auto& definitions = current.fields();
    const auto field = std::find_if(definitions.begin(), definitions.end(), [&](const auto& item) { return item.name == record->field.name; });
    if (record->structure_name != current.name() || record->structure_size != current.size() || field == definitions.end() ||
        field->offset != record->field.offset || field->type != record->field.type)
        return {OffsetStatus::layout_mismatch, 0};
    if (!RangeValid(structure_base, current.size())) return {OffsetStatus::invalid_range, 0};
    return {OffsetStatus::ok, structure_base + field->offset};
}
}
