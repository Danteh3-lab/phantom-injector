#pragma once
#include "phantom/MemoryInspector.hpp"
#include <string>
#include <variant>

namespace phantom {
enum class FieldType { int32, uint32, int64, uint64, float32, float64, pointer64 };
struct FieldDefinition {
    std::string name;
    std::size_t offset;
    FieldType type;
};

class StructureLayout {
public:
    static constexpr std::size_t max_size = 16 * 1024 * 1024;
    static constexpr std::size_t max_fields = 256;
    // Validates field types, bounds and unique names. Throws std::invalid_argument
    // for invalid layouts; all names must be nonempty, NUL-free and <=128 bytes.
    StructureLayout(std::string name, std::size_t size, std::vector<FieldDefinition> fields);
    const std::string& name() const noexcept { return name_; }
    std::size_t size() const noexcept { return size_; }
    const std::vector<FieldDefinition>& fields() const noexcept { return fields_; }
private:
    std::string name_;
    std::size_t size_;
    std::vector<FieldDefinition> fields_;
};

struct PointerValue { std::uint64_t address; }; // Stored x64 pointer bits; never followed automatically.
using FieldValue = std::variant<std::monostate, std::int32_t, std::uint32_t, std::int64_t,
    std::uint64_t, float, double, PointerValue>;
struct FieldResult {
    FieldDefinition definition;
    std::uintptr_t address;
    std::vector<std::byte> bytes; // Exact copied bytes, including partial prefixes.
    FieldValue value; // monostate on any read failure; decoded only after a complete read.
    MemoryError error;
};
enum class StructureStatus { ok, invalid_layout, invalid_address, memory_error };
struct StructureResult {
    std::string name;
    std::uintptr_t address = 0;
    StructureStatus status = StructureStatus::ok;
    MemoryError error; // First failed field, or the invalid base range.
    std::vector<FieldResult> fields; // Definition order; errors do not suppress later fields.
};

class StructureInspector {
public:
    explicit StructureInspector(const MemoryInspector& inspector) : inspector_(inspector) {}
    // Snapshot readability of a nonempty range, not object/type/lifetime validity.
    // At most 16 MiB and MemoryInspector's default region count; copies no bytes.
    MemoryError CheckPointer(std::uintptr_t address, std::size_t size = 1) const;
    // Copies and decodes only declared fields; does not read or require padding.
    // Values use native byte order and IEEE-754 floats (Windows x64 baseline).
    StructureResult Inspect(std::uintptr_t address, const StructureLayout& layout) const;
private:
    const MemoryInspector& inspector_; // Must outlive this inspector.
};
}
