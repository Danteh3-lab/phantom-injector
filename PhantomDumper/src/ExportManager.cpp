#include "phantom/ExportManager.hpp"
#include <algorithm>
#include <fstream>
#include <limits>
#include <locale>
#include <sstream>
#include <stdexcept>
#include <string_view>

namespace phantom {
namespace {
void Utf8(std::string_view text) {
    for (std::size_t cursor = 0; cursor < text.size();) {
        const auto first = static_cast<unsigned char>(text[cursor++]);
        if (first < 0x80) continue;
        unsigned int code = 0;
        unsigned int extra = 0;
        unsigned int minimum = 0;
        if (first >= 0xc2 && first <= 0xdf) { code = first & 0x1f; extra = 1; minimum = 0x80; }
        else if (first >= 0xe0 && first <= 0xef) { code = first & 0x0f; extra = 2; minimum = 0x800; }
        else if (first >= 0xf0 && first <= 0xf4) { code = first & 0x07; extra = 3; minimum = 0x10000; }
        else throw std::invalid_argument("export text is not UTF-8");
        if (extra > text.size() - cursor) throw std::invalid_argument("truncated UTF-8 export text");
        for (unsigned int i = 0; i < extra; ++i) {
            const auto next = static_cast<unsigned char>(text[cursor++]);
            if ((next & 0xc0) != 0x80) throw std::invalid_argument("invalid UTF-8 continuation");
            code = (code << 6) | (next & 0x3f);
        }
        if (code < minimum || code > 0x10ffff || (code >= 0xd800 && code <= 0xdfff))
            throw std::invalid_argument("invalid UTF-8 code point");
    }
}
void Metadata(const ExportMetadata& metadata) {
    if (metadata.capture_id.size() > 256 || metadata.created_at_utc.size() > 256)
        throw std::invalid_argument("export metadata exceeds 256 bytes");
}
std::string JsonString(std::string_view text) {
    Utf8(text);
    static constexpr char hex[] = "0123456789abcdef";
    std::string result = "\"";
    for (const unsigned char value : text) {
        if (value == '"' || value == '\\') { result += '\\'; result += static_cast<char>(value); }
        else if (value < 0x20) { result += "\\u00"; result += hex[value >> 4]; result += hex[value & 0x0f]; }
        else result += static_cast<char>(value);
    }
    result += '"';
    return result;
}
std::string CppString(std::string_view text) {
    Utf8(text);
    // Fixed three-digit octal escapes avoid encoding dependence, literal/code
    // injection and greedy hexadecimal escapes; explicit length preserves NULs.
    static constexpr char octal[] = "01234567";
    std::string result = "std::string_view{\"";
    for (const unsigned char value : text) {
        result += '\\'; result += octal[(value >> 6) & 7]; result += octal[(value >> 3) & 7]; result += octal[value & 7];
    }
    result += "\", " + std::to_string(text.size()) + "}";
    return result;
}
struct TypeInfo { const char* name; std::size_t width; };
TypeInfo Type(FieldType type) {
    switch (type) {
    case FieldType::int32: return {"int32", 4};
    case FieldType::uint32: return {"uint32", 4};
    case FieldType::int64: return {"int64", 8};
    case FieldType::uint64: return {"uint64", 8};
    case FieldType::float32: return {"float32", 4};
    case FieldType::float64: return {"float64", 8};
    case FieldType::pointer64: return {"pointer64", 8};
    default: throw std::invalid_argument("unsupported export field type");
    }
}
template<class Record> std::vector<const Record*> Sorted(const std::vector<Record>& records) {
    std::vector<const Record*> sorted;
    sorted.reserve(records.size());
    for (const auto& record : records) sorted.push_back(&record);
    std::sort(sorted.begin(), sorted.end(), [](const auto* left, const auto* right) {
        return std::lexicographical_compare(left->name.begin(), left->name.end(), right->name.begin(), right->name.end(),
            [](unsigned char a, unsigned char b) { return a < b; });
    });
    return sorted;
}
void Save(const std::filesystem::path& path, const std::string& text) {
    if (text.size() > static_cast<std::size_t>(std::numeric_limits<std::streamsize>::max()))
        throw std::length_error("export exceeds stream size");
    std::ofstream file;
    file.exceptions(std::ios::failbit | std::ios::badbit);
    file.open(path, std::ios::binary | std::ios::trunc);
    file.write(text.data(), static_cast<std::streamsize>(text.size()));
    file.flush();
    file.close();
}
}

std::string ExportManager::Json(const OffsetManager& catalog, const ExportMetadata& metadata) {
    Metadata(metadata);
    std::ostringstream output;
    output.imbue(std::locale::classic());
    output << "{\n  \"schema_version\": 1,\n  \"generator\": \"PhantomDumper\",\n  \"metadata\": {\"capture_id\": "
        << JsonString(metadata.capture_id) << ", \"created_at_utc\": " << JsonString(metadata.created_at_utc)
        << "},\n  \"game\": {\"name\": " << JsonString(catalog.version().game) << ", \"build_id\": "
        << JsonString(catalog.version().build_id) << "},\n  \"modules\": [";
    bool comma = false;
    for (const auto* record : Sorted(catalog.module_offsets())) {
        output << (comma ? ",\n" : "\n") << "    {\"key\": " << JsonString(record->name) << ", \"module_name\": "
            << JsonString(record->module_name) << ", \"module_build_id\": " << JsonString(record->module_build_id)
            << ", \"image_size\": " << record->image_size << ", \"rva\": " << record->rva << ", \"width\": " << record->width << '}';
        comma = true;
    }
    output << (comma ? "\n  ],\n" : "],\n") << "  \"fields\": [";
    comma = false;
    for (const auto* record : Sorted(catalog.field_offsets())) {
        const auto type = Type(record->field.type);
        output << (comma ? ",\n" : "\n") << "    {\"key\": " << JsonString(record->name) << ", \"structure_name\": "
            << JsonString(record->structure_name) << ", \"structure_size\": " << record->structure_size
            << ", \"field_name\": " << JsonString(record->field.name) << ", \"offset\": " << record->field.offset
            << ", \"type\": " << JsonString(type.name) << ", \"width\": " << type.width << '}';
        comma = true;
    }
    output << (comma ? "\n  ]\n}\n" : "]\n}\n");
    return output.str();
}

std::string ExportManager::CppHeader(const OffsetManager& catalog, const ExportMetadata& metadata) {
    Metadata(metadata);
    std::ostringstream output;
    output.imbue(std::locale::classic());
    output << "#pragma once\n#include <array>\n#include <cstdint>\n#include <string_view>\n\nnamespace phantom_dump {\n"
        "inline constexpr std::uint32_t schema_version = 1;\ninline constexpr auto generator = " << CppString("PhantomDumper")
        << ";\ninline constexpr auto game_name = " << CppString(catalog.version().game)
        << ";\ninline constexpr auto game_build_id = " << CppString(catalog.version().build_id)
        << ";\ninline constexpr auto capture_id = " << CppString(metadata.capture_id)
        << ";\ninline constexpr auto created_at_utc = " << CppString(metadata.created_at_utc) << ";\n"
        "enum class FieldKind { int32, uint32, int64, uint64, float32, float64, pointer64 };\n"
        "struct ModuleOffsetRecord {\n    std::string_view key, module_name, module_build_id;\n"
        "    std::uint32_t image_size, rva;\n    std::uint64_t width;\n};\n"
        "struct FieldOffsetRecord {\n    std::string_view key, structure_name;\n    std::uint64_t structure_size;\n"
        "    std::string_view field_name;\n    std::uint64_t offset;\n    FieldKind type;\n    std::uint64_t width;\n};\n"
        "inline constexpr std::array<ModuleOffsetRecord, " << catalog.module_offsets().size() << "> modules{{\n";
    for (const auto* record : Sorted(catalog.module_offsets())) {
        output << "    {" << CppString(record->name) << ", " << CppString(record->module_name) << ", " << CppString(record->module_build_id)
            << ", " << record->image_size << "U, " << record->rva << "U, " << record->width << "ULL},\n";
    }
    output << "}};\ninline constexpr std::array<FieldOffsetRecord, " << catalog.field_offsets().size() << "> fields{{\n";
    for (const auto* record : Sorted(catalog.field_offsets())) {
        const auto type = Type(record->field.type);
        output << "    {" << CppString(record->name) << ", " << CppString(record->structure_name) << ", " << record->structure_size
            << "ULL, " << CppString(record->field.name) << ", " << record->field.offset << "ULL, FieldKind::" << type.name
            << ", " << type.width << "ULL},\n";
    }
    output << "}};\n}\n";
    return output.str();
}
void ExportManager::WriteJson(const std::filesystem::path& path, const OffsetManager& catalog, const ExportMetadata& metadata) {
    const auto text = Json(catalog, metadata);
    Save(path, text);
}
void ExportManager::WriteCppHeader(const std::filesystem::path& path, const OffsetManager& catalog, const ExportMetadata& metadata) {
    const auto text = CppHeader(catalog, metadata);
    Save(path, text);
}
}
