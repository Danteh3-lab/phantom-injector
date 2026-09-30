# PhantomDumper

A separate x64 Windows C++17 diagnostic DLL for development processes you own
or are authorized to inspect. Version 0.5 adds a versioned offset catalog to
module metadata, logging, the synchronous lifecycle, memory inspection, pattern
scanning and known structure inspection. It does not yet discover layouts or
signatures automatically, dump binaries, or generate an SDK.

## Build and test

Install Visual Studio 2022's Desktop development with C++ workload and CMake
3.20 or newer. From the repository root:

```powershell
cmake -S PhantomDumper -B PhantomDumper/build -A x64 -DBUILD_TESTING=ON
cmake --build PhantomDumper/build --config Release
ctest --test-dir PhantomDumper/build -C Release --output-on-failure
```

Output: `PhantomDumper/build/Release/PhantomDumper.dll` with the Visual Studio
generator. The DLL uses the compiler's default shared CRT; the matching Visual
C++ x64 runtime must be available. This project has its own CMake build and
does not participate in `Phantom.sln` or change Phantom.Core/Phantom.UI.

On Linux/macOS, the same CMake project builds only the portable core and its
tests. Native module enumeration and DLL loading require Windows. CI exercises
Windows Debug/Release plus the Linux core, with compiler warnings as errors.
Windows also runs allocated-buffer memory inspection tests; portable tests use
a synthetic backend to exercise error paths deterministically.

## Lifecycle and Phantom integration

`DllMain` is intentionally empty. Loading the DLL alone does not start a dump.
After a normal Windows loader-managed load into your development host, call:

1. `PhantomDumperStart()` with **no arguments**. It takes the first module
   snapshot and appends it to the host process's
   `%TEMP%\PhantomDumper-<pid>.log`.
2. `PhantomDumperSnapshot()` with **no arguments** for another snapshot.
3. `PhantomDumperStop()` with **no arguments** before unloading.

Phantom's existing Execute exported functions feature can call these names;
no injector changes are required. Start reports diagnostic initialization,
independently of whether injection succeeded. This foundation is supported
with standard loader-managed loading, intact headers and normal loader lists.
Other mapping/stealth configurations have not been validated for this DLL.
The included `PhantomDumperSmoke` executable provides an independent test host
using `LoadLibraryW`/`GetProcAddress`/`FreeLibrary`.

For native hosts, `PhantomDumperStartAt(const wchar_t* log_path)` accepts a
valid UTF-16 path to an existing parent directory. Do not pass a path through
Phantom's ANSI string argument UI to this UTF-16 export. Public declarations
are in `include/phantom/Api.h`; exports use a C ABI and Windows calling convention.

| Return value | Meaning |
| --- | --- |
| 0 | Success |
| 1 | Already started, or snapshot requested before start/after stop |
| 2 | Log open/write/flush/close or temporary-path failure |
| 3 | Module enumeration failure |
| 4 | Unexpected internal exception |
| 5 | Empty/null explicit log path |

Failed start leaves the session stopped and retryable. A failed snapshot keeps
the session started so the caller can retry or stop. Stop is idempotent. Calls
are serialized by a mutex and execute entirely on the calling thread; there
are no worker threads or pending asynchronous jobs. No exception crosses the
C ABI. Call exports outside `DllMain` and outside the loader lock. The host
must keep the DLL loaded for every call and ensure **all callers have returned**
before `FreeLibrary`; Stop cannot make an overlapping unload safe.

## Snapshot semantics and logging

`ModuleResolver` uses a Tool Help snapshot of the current process only. It
copies module names, paths, runtime base addresses and image sizes; it does not
dereference returned bases. `ERROR_BAD_LENGTH` is retried up to eight times
during loader churn; any remaining failure returns status 3. A partial module
walk is discarded. The snapshot owns an RAII handle that closes on all paths.
See Microsoft's [Tool Help snapshot documentation](https://learn.microsoft.com/en-us/windows/win32/api/tlhelp32/nf-tlhelp32-createtoolhelp32snapshot)
for enumeration limitations and retry behavior.

These are point-in-time module addresses, **not verified offsets**. A module
may unload after enumeration. Manual mappings, modules removed from loader
lists and data-file loads are not a complete part of this inventory. Tool Help
paths use fixed-size buffers and may be truncated for long paths.

The append-only UTF-8 text log labels base addresses and image sizes separately.
Control characters and backslashes in names/paths are escaped to preserve row
boundaries. Each operation opens, writes and closes the log before returning;
no file handle is retained for DLL detach. I/O failure can leave a partial
record, so a failed snapshot must not be treated as a complete report. Choose
a host-controlled destination with `StartAt` when strict log isolation matters;
the default temp filename is predictable and can include earlier PID reuse.

## Read-only MemoryInspector (phase #2)

`include/phantom/MemoryInspector.hpp` provides a C++ component for later scanners
and structure inspectors. Link native hosts/components against `PhantomDumperCore`.
On Windows its default constructor uses `VirtualQuery` and
`ReadProcessMemory(GetCurrentProcess(), ...)`; it accepts no PID or external
process handle, writes no target memory, and changes no page protections.
The existing C exports and module log remain as documented above; memory reads
are not automatically started or written to those logs by DLL lifecycle calls.

```cpp
#include "phantom/MemoryInspector.hpp"

phantom::MemoryInspector inspector; // Windows: current process.
auto regions = inspector.Enumerate(module.base, module.image_size);
if (regions.error.status == phantom::MemoryStatus::ok) {
    for (const auto& region : regions.regions) {
        // Full native region boundaries, state, protection, type, allocation base.
        // A region can extend beyond the requested interval.
    }
}
auto read = inspector.Read(module.base, 64);
if (read.error.status == phantom::MemoryStatus::ok) {
    // read.bytes contains all 64 requested bytes.
} else {
    // read.bytes contains only the contiguous prefix actually copied.
    // Inspect error.address and error.native_error; do not assume a full read.
}
```

Both operations use the interval `[address, address + size)`, rejecting addition
overflow. Empty intervals succeed without querying/copying; nonempty null reads
are invalid. Enumeration includes free, reserved and inaccessible regions and
retains full Win32 metadata. It is complete-or-error: an error discards the region
list. The default 65,536-region limit is configurable for enumeration. Read
allocations default to at most 16 MiB (configurable per call); reads also stop
after 65,536 region queries. Limits are checked before unbounded work.

Only committed pages with read permission are copied. Guard, no-access,
execute-only, reserved and free regions stop reads. Read permission supports
read-only, read/write, copy-on-write and their executable variants. Protection
modifiers are retained in metadata. Each chunk is checked before an OS-mediated
copy and does not cross a queried region boundary. Query failures report
`query_error`; short or failed copies report `read_error` and retain only copied
bytes. The status `unreadable` describes a rejected page, `invalid_range` an
invalid request, and `limit_exceeded` an exhausted bound. Native Win32 error
codes are preserved where available. C++ allocation/unexpected backend exceptions
can propagate; this API is not an exception-free C ABI.

These are best-effort observations, not atomic snapshots or pointer lifetime
validation. Another thread can change data, protections or mappings between
query and copy. The OS-mediated copy contains access failures, but cannot detect
an address reused for another allocation or guarantee a guard remains untouched
if another thread adds it after the query. Reading can fault pages into memory.
For coherent structures, coordinate inspection with the owning host. A successful
read never guarantees that the same address remains readable after the call.
See Microsoft's [VirtualQuery](https://learn.microsoft.com/en-us/windows/win32/api/memoryapi/nf-memoryapi-virtualquery)
and [ReadProcessMemory](https://learn.microsoft.com/en-us/windows/win32/api/memoryapi/nf-memoryapi-readprocessmemory)
documentation for native behavior.

The injectable `MemoryBackend` is a narrow test seam; it must outlive the inspector.
Portable tests exercise protection filtering, checked arithmetic, traversal limits,
unaligned/cross-region reads, query errors, invalid metadata, short transfers and
query/copy races. Windows tests reserve and commit real pages, verify bytes across
protection boundaries, and cover guard preservation, no-access, execute-only,
reserved/decommitted pages and invalid addresses. The backend is stateless; read
buffers and results belong to the caller. No background work is introduced.

## PatternScanner (phase #3)

`include/phantom/PatternScanner.hpp` adds another C++ component linked through
`PhantomDumperCore`. It consumes MemoryInspector results and never dereferences
source addresses itself. No new C exports or automatic DLL lifecycle work are
introduced. A signature must already be known; a match is a runtime address,
not a validated structure, function or version-independent offset.

```cpp
#include "phantom/PatternScanner.hpp"

phantom::MemoryInspector inspector;
phantom::PatternScanner scanner(inspector);
auto pattern = phantom::Pattern::Parse("48 8B ?? ?? 89");
auto scan = scanner.Scan(module.base, module.image_size, pattern);
if (scan.status == phantom::ScanStatus::ok) {
    // scan.matches contains all observed matches in the readable portions.
    // scan.bytes_skipped records bytes in inaccessible snapshot regions.
} else {
    // Incomplete scan: matches may contain earlier valid observations.
    // For memory failures inspect scan.memory_error, including native_error.
}
```

Parsing accepts ASCII hex pairs in either case and whole-byte wildcards `?` or
`??`, separated by ASCII whitespace. Leading/trailing whitespace is allowed.
Empty patterns, compact strings (`488B`), prefixes (`0x48`), nibble wildcards
(`?F`/`F?`), invalid hex and punctuation are rejected with
`std::invalid_argument`. Text is limited to 64 KiB and patterns to 4,096 bytes.
All-wildcard patterns are valid and subject to the same output limit.

Scans use `[address, address + size)` and reject overflow/nonempty null ranges.
Matches are ascending, include overlaps and must fit entirely inside the
requested range. The scanner first enumerates regions, then reads each readable
portion in bounded chunks. Up to `pattern length - 1` copied bytes are retained
so matches spanning chunk boundaries or adjacent readable regions are found
once. Unreadable regions are skipped and clear the retained overlap: bytes on
opposite sides of a gap cannot form a match. An enumeration or later read failure
ends the scan with `memory_error`; matches wholly inside a copied prefix remain
available. An inaccessible region skipped from the snapshot is distinct from a
page that becomes inaccessible during a later copy, which ends the scan.

`ScanOptions` bounds resource use:

| Option | Default | Behavior |
| --- | --- | --- |
| `chunk_size` | 64 KiB | Read/window chunk; accepted range is 1 byte to 1 MiB. |
| `max_scan_bytes` | 64 MiB | Reject larger intervals before any query/read. |
| `max_matches` | 1,024 | Stop immediately at this many matches. |
| `max_comparisons` | 67,108,864 | Stop before exceeding this number of fixed-byte comparisons. |
| `max_regions` | 65,536 | Passed to MemoryInspector's bounded region walk. |

Zero chunk/match/comparison/region limits are invalid options. For larger images,
choose a smaller section/range or deliberately increase `max_scan_bytes` and the
work budget. Chunk/window memory does not grow with the total scanned interval.
Fixed-byte positions are precomputed so wildcard bytes require no comparisons;
matching is otherwise a straightforward bounded search, not an optimized
multi-pattern engine. Highly repetitive input or long signatures may exhaust the
comparison budget. `bytes_read` counts fetched bytes, even if matching stops
before processing the whole last chunk; `comparisons` counts actual comparisons.
If a failed native read and a scanner limit coincide in its copied prefix, the
native failure takes priority in the returned status.

Only `ScanStatus::ok` indicates completion over readable snapshot portions.
`match_limit` is conservative: reaching the cap stops immediately even if that
match happens to be the last one. `work_limit` and `range_limit` identify the
other scanner limits; region enumeration limits appear as `memory_error` with
`MemoryStatus::limit_exceeded`. Do not interpret partial results as a full scan
with no other matches. An empty scan succeeds without memory access after
argument validation. Allocation/unexpected C++ exceptions can propagate.

As with MemoryInspector, observations are best effort. Chunk overlap can combine
bytes copied at different moments; host synchronization is required for a
coherent scan. Neither matches nor skipped regions guarantee future accessibility
or address identity. Pattern scanning does not resolve relative instructions,
inspect structures, calculate RVAs or export results; those remain later phases.

Portable tests cover malformed signatures, exact/wildcard/overlapping matches,
chunk/region/range boundaries, gaps, resource limits, read/query failures and
comparison with a whole-buffer reference across 200 deterministic randomized
fixtures. Windows page tests also verify a native wildcard match across chunk
and read/write-to-read-only boundaries and skipping a stable guard page.

## StructureInspector (phase #4)

`include/phantom/StructureInspector.hpp` inspects a layout supplied by the host
or obtained from authorized reverse engineering. It remains a C++ component
linked through `PhantomDumperCore`, with every source read going through
MemoryInspector. There are no new C exports or automatic inspection on DLL load.

For example, a development host with a known standard-layout structure can
derive field offsets directly from its source:

```cpp
#include "phantom/StructureInspector.hpp"
#include <cstddef>
#include <cstdint>

struct DevPlayer {
    std::int32_t health;
    float x, y, z;
    std::uint64_t next_address; // x64 pointer bits for this fixture.
};
DevPlayer player{100, 1.0f, 2.0f, 3.0f, 0};
phantom::StructureLayout layout("DevPlayer", sizeof(DevPlayer), {
    {"health", offsetof(DevPlayer, health), phantom::FieldType::int32},
    {"x", offsetof(DevPlayer, x), phantom::FieldType::float32},
    {"y", offsetof(DevPlayer, y), phantom::FieldType::float32},
    {"z", offsetof(DevPlayer, z), phantom::FieldType::float32},
    {"next", offsetof(DevPlayer, next_address), phantom::FieldType::pointer64}
});
phantom::MemoryInspector memory;
phantom::StructureInspector structures(memory);
auto result = structures.Inspect(reinterpret_cast<std::uintptr_t>(&player), layout);
if (result.fields[0].error.status == phantom::MemoryStatus::ok) {
    auto health = std::get<std::int32_t>(result.fields[0].value);
    // Use health as an observed value; validate game-specific semantics separately.
}
auto range_check = structures.CheckPointer(reinterpret_cast<std::uintptr_t>(&player), sizeof(player));
// range_check.status == ok is snapshot readability, not lifetime/type validity.
```

Layouts own their structure/field names and descriptors. Construction validates
nonempty, NUL-free names of at most 128 bytes, unique field names, a size from
1 byte to 16 MiB, 1 to 256 fields, supported types, and every field's complete
width fitting inside the declared extent. Invalid definitions throw
`std::invalid_argument` before any target access. Overlapping fields with distinct
names are permitted for unions or aliases; unaligned fields are supported.

| `FieldType` | Width | `FieldValue` alternative |
| --- | --- | --- |
| `int32` / `uint32` | 4 bytes | `std::int32_t` / `std::uint32_t` |
| `int64` / `uint64` | 8 bytes | `std::int64_t` / `std::uint64_t` |
| `float32` / `float64` | 4 / 8 bytes | `float` / `double` |
| `pointer64` | 8 bytes | `PointerValue` with the stored 64-bit address bits |

Values use native byte order with IEEE-754 floats, matching the x64 Windows
baseline. The portable core/tests use their host's native order. No source
buffer is cast to a structure or dereferenced for decoding: scalars are copied
from owned byte buffers. Float NaNs, integer extremes and null pointer values
are preserved; no health range, object identity, pointee type or application
invariant is inferred. Coordinate vectors can be defined as separate float
fields. Strings, arrays, nested structures and automatic pointer chains are
outside this phase.

`Inspect` validates the full base interval for null/overflow before reading, then
copies each declared field independently in definition order. It does not read
padding or require the whole structure to be readable. Each `FieldResult` owns
its descriptor, runtime field address, copied bytes, typed value and MemoryError.
Only a complete successful field read is decoded; every failure leaves the value
as `std::monostate`, even if the OS reported a full transfer count. Partial raw
bytes and native error codes remain available. Later fields are still attempted.
`StructureStatus::ok` means all declared fields were read successfully;
`memory_error` means at least one failed and the aggregate error identifies the
first failure in definition order. Invalid base intervals return
`invalid_address` with no fields or target access. A moved-from empty layout is
rejected as `invalid_layout`. Allocation/unexpected C++ exceptions can propagate.

`CheckPointer(address, size = 1)` performs bounded region metadata checks only.
It rejects null, empty, overflowed or over-16-MiB intervals and requires all
covered pages to be committed/readable according to MemoryInspector. Guard,
no-access, execute-only, reserved and free pages fail. Query errors and the
default 65,536-region enumeration limit are preserved. It copies no target
bytes, follows no stored pointers, and cannot guarantee a later read succeeds.
Pointer fields are simply values; explicitly call CheckPointer on a stored
address and an intended extent when that check is useful.

These are best-effort field observations rather than an atomic object snapshot.
The host must coordinate writers/lifetimes for coherent structures. A readable
address may hold a different allocation by the next operation, and successful
field reads do not establish that the supplied layout matches the object.

Portable tests cover invalid/bounded layouts, all scalar types, unaligned reads,
pointer bits, numeric extremes, NaNs, padding, cross-region partial fields,
continued inspection after errors and native query/copy failures. Windows page
tests verify typed reads across RW/RO boundaries, partial guard-boundary fields,
and pointer checks without clearing a stable guard page.

## OffsetManager (phase #5)

`include/phantom/OffsetManager.hpp` stores validated offset records for one
game/build identity. It performs metadata validation and checked arithmetic,
without querying or reading target memory. Native consumers link through
`PhantomDumperCore`; existing C exports and DLL lifecycle behavior are unchanged.

```cpp
#include "phantom/OffsetManager.hpp"

phantom::VersionInfo version{"development-game", "build-42"};
phantom::OffsetManager offsets(version);
// module is a ModuleInfo snapshot; candidate is a known address, such as a
// validated PatternScanner match. The host supplies an image-specific build ID.
offsets.AddModuleAddress("registry", module, candidate, 8, "engine-image-build-19");
offsets.AddField("player.health", player_layout, "health");

// Supply fresh module metadata, game identity and module build identity.
auto module_address = offsets.ResolveModule("registry", current_module,
    current_version, current_module_build_id);
if (module_address.status == phantom::OffsetStatus::ok) {
    // module_address.address == current_module.base + the recorded RVA.
    // Check current readability with MemoryInspector before inspecting bytes.
}
auto field_address = offsets.ResolveField("player.health", current_player_base,
    current_player_layout, current_version);
```

The two record types preserve different coordinate systems:

| Record | Stored offset | Identity/bounds metadata |
| --- | --- | --- |
| `ModuleOffset` | 32-bit RVA from image base | Module name, image build ID, image size and inspected span width |
| `FieldOffset` | Offset from structure base | Structure name/extent and the chosen field's name, offset and type |

`AddModuleAddress` converts an absolute observation to an RVA. The nonnull image
interval must not overflow; the address and its nonempty width must lie wholly
inside that image. RVA zero and the final image byte are valid. Image RVAs are
not disk file offsets. The catalog retains no observed runtime base or module
path, allowing ASLR rebasing and deployment path changes. `AddField` copies a
field from a validated StructureLayout; nonexistent fields are rejected. Field
offset zero and distinct aliases are valid. Catalog keys are globally unique
across both record types; typed lookups do not reinterpret one kind as the other.

Every catalog has an immutable `VersionInfo` (game name plus build ID).
`ResolveModule` requires an exact match for this game/build identity, module name,
module build ID and image size, then checks the current image interval before
rebasing the RVA. `ResolveField` requires the same game/build identity and a
matching structure name/extent plus the selected field's name/offset/type, then
checks the whole structure interval before adding the field offset. Other fields
are not part of that record's comparison. Module names and build IDs compare
exactly, including case. Construct a new catalog for a new game build.

Version/build identifiers are **host-supplied labels or fingerprints**, not
automatically computed or authenticated. Tool Help supplies names, bases and
image sizes, but cannot establish the supplied build ID. The host should derive
stable build IDs from its own build metadata or an appropriate image fingerprint
and supply the current identity independently. Reusing an old ID on a changed
image can defeat this check; matching sizes or labels alone do not prove bytes
are unchanged. Records may represent unverified candidate addresses until the
host establishes their meaning.

| `OffsetStatus` | Meaning |
| --- | --- |
| `ok` | Metadata matched and arithmetic produced an address. |
| `not_found` | No record of the requested kind has this key. |
| `version_mismatch` | Game or game build identity differs. |
| `module_mismatch` | Module name, image build ID or image size differs. |
| `layout_mismatch` | Structure/selected-field metadata differs or the field is missing. |
| `invalid_range` | Current module/structure base is null or its interval overflows. |

Failed resolution returns address zero. Success guarantees neither readability,
pointer lifetime nor object identity; use MemoryInspector/StructureInspector for
subsequent observations and coordinate host lifetimes. No stale address fallback,
pointer following, offset discovery or target writes are performed.

All catalog keys and identity text must be nonempty, NUL-free and at most 128
bytes. Invalid/duplicate insertions throw `std::invalid_argument` without adding
a record. The combined module/field limit is 4,096 records; exhausting it throws
`std::length_error` without overwrite or eviction. Const accessors expose records
and root version metadata for later export. Allocation exceptions can propagate.
Catalog copies own their metadata; additions can invalidate references to record
elements. Callers must coordinate concurrent mutation/access.

Portable tests cover RVA capture/rebasing, image and field boundaries, overflow,
changed versions/images/layouts, typed lookup separation, failed insertion
recovery, metadata copies and the combined record limit. Windows tests use real
Tool Help host-module metadata for an RVA round-trip and resolve a known field to
its native typed-inspection address. JSON/C++ serialization remains phase #6.

## Components and follow-up PRs

- `ModuleResolver`: Windows module metadata snapshot.
- `Logger`: format and append a snapshot without retaining handles.
- `Runtime`: transactional initialization, serialized snapshots, stop/restart.
- `MemoryInspector`: bounded region enumeration and read-only copies.
- `PatternScanner`: known signature parsing and bounded wildcard matching.
- `StructureInspector`: validated known layouts, pointer checks and typed field reads.
- `OffsetManager`: versioned module RVAs and structure field offset records.
- `Exports`/`dllmain`: explicit C API with exception containment and minimal entry point.

Core tests cover formatting, large addresses, log escaping, initialization
failures, retry, append behavior, concurrent snapshots and shutdown/restart.
Windows smoke tests validate real module bases, Unicode output paths, named
exports and repeated load/start/snapshot/stop/unload cycles. They do not test
anti-cheat behavior or Phantom's injection methods.

The final planned phase adds JSON/C++ ExportManager and end-to-end coverage.
