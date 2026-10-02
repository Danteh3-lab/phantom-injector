#pragma once
#include "phantom/OffsetManager.hpp"
#include <filesystem>

namespace phantom {
struct ExportMetadata {
    std::string capture_id;
    std::string created_at_utc; // Optional host-supplied text, not automatically generated/parsed.
};
class ExportManager {
public:
    // Schema v1, sorted by key. Text must be valid UTF-8; metadata <=256 bytes/field.
    // Invalid text throws invalid_argument. Allocation exceptions can propagate.
    static std::string Json(const OffsetManager& catalog, const ExportMetadata& metadata = {});
    // Standalone C++17 header in namespace phantom_dump. Keys remain data, not identifiers.
    static std::string CppHeader(const OffsetManager& catalog, const ExportMetadata& metadata = {});
    // Render before opening; write/truncate a caller-selected file and check flush/close.
    // I/O errors throw ios_base::failure and can leave a partial file. No parent creation.
    static void WriteJson(const std::filesystem::path& path, const OffsetManager& catalog,
        const ExportMetadata& metadata = {});
    static void WriteCppHeader(const std::filesystem::path& path, const OffsetManager& catalog,
        const ExportMetadata& metadata = {});
};
}
