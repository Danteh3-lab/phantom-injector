#include "phantom/StructureInspector.hpp"
#include <algorithm>
#include <cmath>
#include <cstring>
#include <iostream>
#include <limits>
#include <stdexcept>
#include <system_error>
#include <utility>

namespace {
void Check(bool condition, const char* message) {
    if (!condition) throw std::runtime_error(message);
}
void Reject(std::string name, std::size_t size, std::vector<phantom::FieldDefinition> fields) {
    try { (void)phantom::StructureLayout(std::move(name), size, std::move(fields)); }
    catch (const std::invalid_argument&) { return; }
    throw std::runtime_error("invalid layout accepted");
}
class Fixture final : public phantom::MemoryBackend {
public:
    static constexpr std::uintptr_t base = 0x123456780000ULL;
    std::vector<std::byte> data = std::vector<std::byte>(64, std::byte{0});
    std::vector<phantom::MemoryRegion> regions = {{base, base, data.size(), 0x1000, 0x04, 0x20000}};
    mutable std::size_t copies = 0;
    mutable std::size_t queries = 0;
    std::uintptr_t query_failure = 0;
    std::uintptr_t copy_failure = 0;
    std::size_t partial_bytes = 0;
    template<class T> void Put(std::size_t offset, T value) {
        Check(offset <= data.size() && sizeof(T) <= data.size() - offset, "fixture write within buffer");
        std::memcpy(data.data() + offset, &value, sizeof(value));
    }
    phantom::MemoryRegion Query(std::uintptr_t address) const override {
        ++queries;
        if (address != query_failure) {
            for (const auto& region : regions)
                if (address >= region.base && address - region.base < region.size) return region;
        }
        throw std::system_error(487, std::system_category(), "synthetic query failure");
    }
    phantom::MemoryCopyResult Copy(std::uintptr_t address, std::byte* output, std::size_t size) const override {
        ++copies;
        const auto offset = static_cast<std::size_t>(address - base);
        Check(offset <= data.size() && size <= data.size() - offset, "fixture read within buffer");
        const auto count = address == copy_failure ? std::min(size, partial_bytes) : size;
        std::copy_n(data.data() + offset, count, output);
        return {count, address == copy_failure ? 299u : 0u};
    }
};
}
int main() {
    try {
        using phantom::FieldType;
        using phantom::StructureLayout;
        using phantom::StructureStatus;
        using phantom::MemoryStatus;
        const phantom::FieldDefinition health{"health", 0, FieldType::int32};
        Reject("", 4, {health});
        Reject(std::string(129, 'x'), 4, {health});
        Reject(std::string("X\0Y", 3), 4, {health});
        Reject("Player", 0, {health});
        Reject("Player", StructureLayout::max_size + 1, {health});
        Reject("Player", 4, {});
        Reject("Player", 4, {{"", 0, FieldType::int32}});
        Reject("Player", 4, {{std::string(129, 'x'), 0, FieldType::int32}});
        Reject("Player", 4, {{std::string("x\0y", 3), 0, FieldType::int32}});
        Reject("Player", 8, {health, health});
        Reject("Player", 4, {{"unknown", 0, static_cast<FieldType>(999)}});
        Reject("Player", 4, {{"outside", 4, FieldType::int32}});
        Reject("Player", 4, {{"overflow", std::numeric_limits<std::size_t>::max(), FieldType::uint64}});
        Reject("Player", 7, {{"too_wide", 0, FieldType::uint64}});
        std::vector<phantom::FieldDefinition> many;
        for (std::size_t i = 0; i < StructureLayout::max_fields; ++i)
            many.push_back({"alias" + std::to_string(i), 0, FieldType::int32});
        Check(StructureLayout(std::string(128, 's'), 4, many).fields().size() == StructureLayout::max_fields,
            "bounded overlapping aliases accepted");
        many.push_back({"extra", 0, FieldType::int32});
        Reject("Player", 4, std::move(many));
        Check(StructureLayout("Large", StructureLayout::max_size,
            {{std::string(128, 'f'), StructureLayout::max_size - 8, FieldType::uint64}}).size() == StructureLayout::max_size,
            "exact maximum size/name/field end accepted");

        Fixture fixture;
        const auto base = Fixture::base;
        fixture.Put<std::int32_t>(1, -123); // Intentionally unaligned source fields.
        fixture.Put<std::uint32_t>(5, std::numeric_limits<std::uint32_t>::max());
        fixture.Put<std::int64_t>(9, std::numeric_limits<std::int64_t>::min());
        fixture.Put<std::uint64_t>(17, std::numeric_limits<std::uint64_t>::max());
        fixture.Put<float>(25, -12.5f);
        fixture.Put<double>(29, 1234.5);
        fixture.Put<std::uint64_t>(37, base + 56);
        const StructureLayout layout("Player", 45, {{"health", 1, FieldType::int32}, {"flags", 5, FieldType::uint32},
            {"signed64", 9, FieldType::int64}, {"unsigned64", 17, FieldType::uint64}, {"x", 25, FieldType::float32},
            {"score", 29, FieldType::float64}, {"next", 37, FieldType::pointer64}});
        phantom::MemoryInspector memory(fixture);
        phantom::StructureInspector inspector(memory);
        const auto result = inspector.Inspect(base, layout);
        Check(result.status == StructureStatus::ok && result.name == "Player" && result.address == base &&
            result.fields.size() == 7 && fixture.copies == 7, "inspect copies only declared fields");
        Check(std::get<std::int32_t>(result.fields[0].value) == -123 && std::get<std::uint32_t>(result.fields[1].value) == std::numeric_limits<std::uint32_t>::max() &&
            std::get<std::int64_t>(result.fields[2].value) == std::numeric_limits<std::int64_t>::min() &&
            std::get<std::uint64_t>(result.fields[3].value) == std::numeric_limits<std::uint64_t>::max(), "signed/unsigned widths decoded without loss");
        Check(std::get<float>(result.fields[4].value) == -12.5f && std::get<double>(result.fields[5].value) == 1234.5 &&
            std::get<phantom::PointerValue>(result.fields[6].value).address == base + 56, "floats and pointer bits decoded");
        Check(result.fields[0].address == base + 1 && result.fields[0].definition.offset == 1 && result.fields[0].bytes.size() == 4,
            "field metadata and owned byte copy retained");
        const auto copies = fixture.copies;
        Check(inspector.CheckPointer(base, 64).status == MemoryStatus::ok && inspector.CheckPointer(base + 1, 3).status == MemoryStatus::ok,
            "unaligned readable ranges pass metadata check");
        Check(fixture.copies == copies, "pointer check never copies target bytes");
        const auto queries = fixture.queries;
        Check(inspector.CheckPointer(0).status == MemoryStatus::invalid_range && inspector.CheckPointer(base, 0).status == MemoryStatus::invalid_range,
            "null and empty pointer checks rejected");
        Check(inspector.CheckPointer(std::numeric_limits<std::uintptr_t>::max() - 1, 2).status == MemoryStatus::invalid_range &&
            inspector.CheckPointer(base, StructureLayout::max_size + 1).status == MemoryStatus::limit_exceeded, "overflow and excessive pointer range rejected");
        Check(inspector.Inspect(0, layout).status == StructureStatus::invalid_address &&
            inspector.Inspect(std::numeric_limits<std::uintptr_t>::max() - 10, layout).status == StructureStatus::invalid_address && fixture.queries == queries,
            "invalid base interval never touches backend");
        fixture.Put<std::uint64_t>(37, 0);
        const auto null_field = inspector.Inspect(base, layout);
        Check(null_field.status == StructureStatus::ok && std::get<phantom::PointerValue>(null_field.fields[6].value).address == 0,
            "null pointer stored as value, not automatically followed");
        fixture.Put<float>(25, std::numeric_limits<float>::quiet_NaN());
        Check(std::isnan(std::get<float>(inspector.Inspect(base, layout).fields[4].value)), "NaN retained without semantic assumptions");

        // A field crossing a protection boundary is incomplete, but later fields survive.
        fixture.regions = {{base, base, 27, 0x1000, 0x04, 0x20000}, {base + 27, base, 10, 0x1000, 0x104, 0x20000},
            {base + 37, base, 27, 0x1000, 0x02, 0x20000}};
        const auto guarded = inspector.Inspect(base, layout);
        Check(guarded.status == StructureStatus::memory_error && guarded.error.status == MemoryStatus::unreadable && guarded.error.address == base + 27,
            "structure status identifies first failed field");
        Check(guarded.fields[4].bytes.size() == 2 && std::holds_alternative<std::monostate>(guarded.fields[4].value) &&
            guarded.fields[5].bytes.empty() && std::holds_alternative<std::monostate>(guarded.fields[5].value) &&
            guarded.fields[6].error.status == MemoryStatus::ok, "partial raw field is not decoded and later readable field succeeds");
        Check(inspector.CheckPointer(base, 45).status == MemoryStatus::unreadable && inspector.CheckPointer(base, 45).address == base + 27,
            "pointer check rejects range spanning guard");
        // Inaccessible padding is irrelevant when the declared fields are readable.
        const StructureLayout sparse("Sparse", 45, {{"before", 1, FieldType::int32}, {"after", 37, FieldType::pointer64}});
        Check(inspector.Inspect(base, sparse).status == StructureStatus::ok, "inspect does not require readable padding");
        fixture.regions[1].state = 0x2000; fixture.regions[1].protection = 0x04;
        Check(inspector.CheckPointer(base + 27).status == MemoryStatus::unreadable, "reserved readable-looking region rejected");
        fixture.regions[1].state = 0x10000;
        Check(inspector.CheckPointer(base + 27).status == MemoryStatus::unreadable, "free region rejected");
        fixture.regions = {{base, base, 64, 0x1000, 0x04, 0x20000}};
        fixture.copy_failure = base + 1; fixture.partial_bytes = 2;
        const auto partial = inspector.Inspect(base, layout);
        Check(partial.status == StructureStatus::memory_error && partial.error.native_error == 299 && partial.error.address == base + 3 &&
            partial.fields[0].bytes.size() == 2 && std::holds_alternative<std::monostate>(partial.fields[0].value) &&
            partial.fields[1].error.status == MemoryStatus::ok, "partial native failure preserved without decoding or suppressing later fields");
        fixture.partial_bytes = 4;
        const auto failed_full = inspector.Inspect(base, layout);
        Check(failed_full.fields[0].bytes.size() == 4 && std::holds_alternative<std::monostate>(failed_full.fields[0].value),
            "native failure never decoded even with full transfer count");
        fixture.copy_failure = 0; fixture.query_failure = base + 1;
        const auto failed_query = inspector.Inspect(base, layout);
        Check(failed_query.fields[0].error.status == MemoryStatus::query_error && failed_query.error.native_error == 487 &&
            failed_query.fields[1].error.status == MemoryStatus::ok, "field query error retained and later queries continue");
        Check(inspector.CheckPointer(base + 1).native_error == 487, "pointer query error propagated");
        fixture.query_failure = 0;
        auto moved = sparse;
        const auto moved_to = std::move(moved);
        Check(inspector.Inspect(base, moved_to).status == StructureStatus::ok && inspector.Inspect(base, moved).status == StructureStatus::invalid_layout,
            "moved-from layout safely rejected");
        std::cout << "StructureInspector checks passed\n";
        return 0;
    } catch (const std::exception& error) { std::cerr << error.what() << '\n'; return 1; }
}
