#include "phantom/StructureInspector.hpp"
#include <algorithm>
#include <cstring>
#include <limits>
#include <stdexcept>
#include <string_view>
#include <unordered_set>
#include <utility>

namespace phantom {
namespace {
std::size_t Width(FieldType type) {
    switch (type) {
    case FieldType::int32: case FieldType::uint32: case FieldType::float32: return 4;
    case FieldType::int64: case FieldType::uint64: case FieldType::float64: case FieldType::pointer64: return 8;
    default: return 0;
    }
}
bool NameValid(const std::string& name) {
    return !name.empty() && name.size() <= 128 && name.find('\0') == std::string::npos;
}
bool RangeValid(std::uintptr_t address, std::size_t size) {
    return address != 0 && size != 0 && size <= std::numeric_limits<std::uintptr_t>::max() - address;
}
template<class T> T Decode(const std::vector<std::byte>& bytes) {
    T value;
    // Copy from our owned buffer; no alignment assumption about the source field.
    std::memcpy(&value, bytes.data(), sizeof(value));
    return value;
}
FieldValue DecodeField(FieldType type, const std::vector<std::byte>& bytes) {
    switch (type) {
    case FieldType::int32: return Decode<std::int32_t>(bytes);
    case FieldType::uint32: return Decode<std::uint32_t>(bytes);
    case FieldType::int64: return Decode<std::int64_t>(bytes);
    case FieldType::uint64: return Decode<std::uint64_t>(bytes);
    case FieldType::float32: return Decode<float>(bytes);
    case FieldType::float64: return Decode<double>(bytes);
    case FieldType::pointer64: return PointerValue{Decode<std::uint64_t>(bytes)};
    default: throw std::logic_error("invalid validated field type");
    }
}
static_assert(sizeof(float) == 4 && sizeof(double) == 8 &&
    std::numeric_limits<float>::is_iec559 && std::numeric_limits<double>::is_iec559,
    "StructureInspector requires IEEE-754 32/64-bit floating point");
}

StructureLayout::StructureLayout(std::string name, std::size_t size, std::vector<FieldDefinition> fields)
    : name_(std::move(name)), size_(size), fields_(std::move(fields)) {
    if (!NameValid(name_) || size_ == 0 || size_ > max_size || fields_.empty() || fields_.size() > max_fields)
        throw std::invalid_argument("invalid structure name, size or field count");
    std::unordered_set<std::string_view> names;
    for (const auto& field : fields_) {
        const auto width = Width(field.type);
        if (!NameValid(field.name) || width == 0 || field.offset > size_ || width > size_ - field.offset ||
            !names.insert(field.name).second)
            throw std::invalid_argument("invalid field name, type, bounds or duplicate name");
    }
}

MemoryError StructureInspector::CheckPointer(std::uintptr_t address, std::size_t size) const {
    if (!RangeValid(address, size)) return {MemoryStatus::invalid_range, address, 0};
    if (size > StructureLayout::max_size) return {MemoryStatus::limit_exceeded, address, 0};
    const auto result = inspector_.Enumerate(address, size);
    if (result.error.status != MemoryStatus::ok) return result.error;
    for (const auto& region : result.regions)
        if (!region.readable()) return {MemoryStatus::unreadable, std::max(address, region.base), 0};
    return {};
}

StructureResult StructureInspector::Inspect(std::uintptr_t address, const StructureLayout& layout) const {
    StructureResult result;
    result.name = layout.name();
    result.address = address;
    if (layout.fields().empty()) { result.status = StructureStatus::invalid_layout; return result; }
    if (!RangeValid(address, layout.size())) {
        result.status = StructureStatus::invalid_address;
        result.error = {MemoryStatus::invalid_range, address, 0};
        return result;
    }
    result.fields.reserve(layout.fields().size());
    for (const auto& field : layout.fields()) {
        const auto field_address = address + field.offset; // Validated layout and full base interval.
        const auto width = Width(field.type);
        auto read = inspector_.Read(field_address, width, width);
        FieldResult inspected{field, field_address, std::move(read.bytes), std::monostate{}, read.error};
        if (inspected.error.status == MemoryStatus::ok) inspected.value = DecodeField(field.type, inspected.bytes);
        else {
            if (result.status == StructureStatus::ok) result.error = inspected.error;
            result.status = StructureStatus::memory_error;
        }
        result.fields.push_back(std::move(inspected));
    }
    return result;
}
}
