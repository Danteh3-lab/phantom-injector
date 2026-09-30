#include "fixture.hpp"
#include <iostream>

using namespace phantom_dump;
constexpr char expected_capture[] = "capture\"\\\n\t\xc3\xa9\0tail";
static_assert(schema_version == 1 && generator == "PhantomDumper");
static_assert(game_name == "dev-\xe6\xb5\x8b\xe8\xaf\x95" && game_build_id == "fixture-build-1");
static_assert(capture_id == std::string_view{expected_capture, sizeof(expected_capture) - 1});
static_assert(created_at_utc == "2026-01-01T00:00:00Z");
static_assert(modules.size() == 1 && modules[0].key == "z.marker" && modules[0].module_build_id == "fixture-image-1");
static_assert(modules[0].width == 4 && modules[0].rva < modules[0].image_size && modules[0].width <= modules[0].image_size - modules[0].rva);
static_assert(fields.size() == 7 && fields[0].key == "a.health" && fields[1].key == "b.next");
static_assert(fields[0].field_name == "health" && fields[0].offset == 4 && fields[0].type == FieldKind::int32 && fields[0].width == 4);
static_assert(fields[1].field_name == "next" && fields[1].type == FieldKind::pointer64 && fields[1].width == 8);
static_assert(fields[1].offset + fields[1].width <= fields[1].structure_size);
static_assert(fields[2].key == "c.marker" && fields[2].type == FieldKind::uint32 && fields[2].width == 4);
static_assert(fields[3].key == "d.x" && fields[3].type == FieldKind::float32 && fields[3].width == 4);
static_assert(fields[4].key == "e.counter" && fields[4].type == FieldKind::int64 && fields[4].width == 8);
static_assert(fields[5].key == "f.ticks" && fields[5].type == FieldKind::uint64 && fields[5].width == 8);
static_assert(fields[6].key == "g.score" && fields[6].type == FieldKind::float64 && fields[6].width == 8);
int main() { std::cout << "Standalone generated C++17 header checks passed\n"; }
