"""Independently parse the end-to-end fixture's JSON with the standard library."""
import json
import pathlib
import sys


def check(condition, message):
    if not condition:
        raise AssertionError(message)


def unique_object(pairs):
    result = {}
    for key, value in pairs:
        check(key not in result, f"duplicate JSON member: {key}")
        result[key] = value
    return result


def reject_constant(value):
    raise AssertionError(f"non-JSON numeric constant: {value}")


directory = pathlib.Path(sys.argv[1])
with (directory / "fixture.json").open(encoding="utf-8") as file:
    report = json.load(file, object_pairs_hook=unique_object, parse_constant=reject_constant)
check(set(report) == {"schema_version", "generator", "metadata", "game", "modules", "fields"}, "schema members")
check(report["schema_version"] == 1 and report["generator"] == "PhantomDumper", "schema/generator metadata")
check(report["game"] == {"name": "dev-测试", "build_id": "fixture-build-1"}, "Unicode game/build identity")
check(report["metadata"] == {"capture_id": 'capture"\\\n\té\0tail', "created_at_utc": "2026-01-01T00:00:00Z"}, "escaped/NUL capture metadata")
check(len(report["modules"]) == 1, "one known module record")
module = report["modules"][0]
check(set(module) == {"key", "module_name", "module_build_id", "image_size", "rva", "width"}, "module members")
check(module["key"] == "z.marker" and module["module_build_id"] == "fixture-image-1", "module identity")
check(isinstance(module["module_name"], str) and module["module_name"], "native or portable module name")
for key in ("image_size", "rva", "width"):
    check(type(module[key]) is int, f"integer module metadata: {key}")
check(module["width"] == 4 and 0 <= module["rva"] <= module["image_size"] - 4, "checked image span")
fields = report["fields"]
check([item["key"] for item in fields] == ["a.health", "b.next", "c.marker", "d.x", "e.counter", "f.ticks", "g.score"], "deterministic field ordering")
for item in fields:
    check(set(item) == {"key", "structure_name", "structure_size", "field_name", "offset", "type", "width"}, "field members")
    check(item["structure_name"] == "DevPlayer", "known layout identity")
    for key in ("structure_size", "offset", "width"):
        check(type(item[key]) is int, f"integer field metadata: {key}")
    check(0 <= item["offset"] <= item["structure_size"] - item["width"], "checked field span")
check(fields[0]["field_name"] == "health" and fields[0]["offset"] == 4 and fields[0]["type"] == "int32" and fields[0]["width"] == 4, "known health field")
check(fields[1]["field_name"] == "next" and fields[1]["type"] == "pointer64" and fields[1]["width"] == 8, "known pointer field")
for index, name, kind, width in ((2, "marker", "uint32", 4), (3, "x", "float32", 4), (4, "counter", "int64", 8),
                                (5, "ticks", "uint64", 8), (6, "score", "float64", 8)):
    check(fields[index]["field_name"] == name and fields[index]["type"] == kind and fields[index]["width"] == width, f"typed field metadata: {name}")
with (directory / "empty.json").open(encoding="utf-8") as file:
    empty = json.load(file, object_pairs_hook=unique_object, parse_constant=reject_constant)
check(empty["modules"] == [] and empty["fields"] == [], "empty JSON arrays")
check(empty["game"] == {"name": "empty-game", "build_id": "build-0"}, "empty catalog identity")
check(empty["metadata"] == {"capture_id": "", "created_at_utc": ""}, "optional metadata defaults")
print("Independent JSON schema and byte/Unicode round-trip checks passed")
