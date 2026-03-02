# zig-pe

Reflective PE loader written in Zig. Loads and executes native and .NET PE files directly from memory.

## Features

### PE Loading Pipeline

- [x] Parse DOS and NT headers (PE32 and PE32+ at runtime)
- [x] Map sections into allocated memory
- [x] Resolve imports (name and ordinal, PE32 4-byte / PE32+ 8-byte thunks)
- [x] Apply base relocations (HIGHLOW, DIR64, ARM_MOV32, THUMB_MOV32)
- [x] Resolve delayed imports (DataDirectory\[13\], modern RVA format)
- [x] Register exception handlers (RtlAddFunctionTable, x64/ARM64 only)
- [x] Set per-section memory protections
- [x] Invoke TLS callbacks (DLL_PROCESS_ATTACH)
- [x] Execute entry point via CreateThread
- [x] Cleanup (unregister exception tables, free memory)

### Advanced Security Features

- [x] Security Cookie Initialization (`__security_cookie` for /GS buffer security)
- [x] CFG (Control Flow Guard) - Registers valid call targets via `SetProcessValidCallTargets`
- [x] SxS / Activation Context - Activates embedded manifests for GUI applications
- [x] Bound Import Directory invalidation

### Export Table Resolution

Utility functions for resolving exports from a loaded PE image:

- `getExportByName(base, ntheaders, name)` — resolve by name
- `getExportByOrdinal(base, ntheaders, ordinal)` — resolve by ordinal

Handles forwarded exports automatically by loading the target DLL (e.g., `"NTDLL.RtlAllocateHeap"` resolves to the actual function in ntdll.dll).

### API Set Resolution

Automatically resolves Windows API sets (`api-ms-win-*`, `ext-ms-win-*`) to their actual host DLLs using the PEB ApiSetMap. This enables loading PEs that import from virtual API set DLLs.

### Utility Functions

- `utils.detect_platform(buffer)` — Detect if PE is 32-bit or 64-bit
- `utils.is_dotnet_assembly(ntheaders)` — Check if PE is a .NET assembly
- `utils.getDotNetVersion(buffer)` — Extract .NET runtime version string from metadata
- `utils.rvaToFileOffset(buffer, rva)` — Convert RVA to raw file offset

### Compatibility

- [x] Native compiled binary execution (x86, x86_64, ARM, ARM64)
- [x] .NET compiled binary execution via CLR hosting
- [x] Command-line argument passing to both native and .NET executables
- [x] Architecture validation (PE bitness must match host process)

### Supported Machine Types

| Architecture | Machine Code | Bitness |
|--------------|--------------|---------|
| i386         | 0x014c       | 32-bit  |
| AMD64        | 0x8664       | 64-bit  |
| IA64         | 0x0200       | 64-bit  |
| ARM (ARMNT)  | 0x01C4       | 32-bit  |
| ARM64        | 0xAA64       | 64-bit  |

## Prerequisites

- Zig compiler (latest version recommended)
- Windows OS (the project uses Windows-specific APIs)

## Building the Project

1. Clone the repository:
   ```
   git clone https://github.com/Thoxy67/zig-pe.git
   cd zig-pe
   ```

2. Build the project:
   ```
   zig build
   ```

### Build Options

```bash
zig build -Ddotnet=false  # Disable .NET support (enabled by default)
```

### Build Targets

```bash
zig build                 # Build all targets
zig build run-putty64     # Run 64-bit native PE example
zig build run-putty32     # Run 32-bit native PE example
zig build run-dotnet      # Run .NET assembly example
zig build test            # Run unit tests
```

## Usage

### Basic Usage (Embedded PE)

```zig
const pe = @import("pe");

pub fn main() !void {
    // Load and execute an embedded PE file
    try pe.RunPE.init(@embedFile("bin/app.exe")).run();
}
```

### With Command-Line Arguments

```zig
const pe = @import("pe");

pub fn main() !void {
    var loader = pe.RunPE.init(@embedFile("bin/app.exe"));
    try loader.runWithArgs(&.{ "arg1", "arg2", "arg3" });
}
```

### Loading from File

```zig
const std = @import("std");
const pe = @import("pe");

pub fn main() !void {
    var gpa = std.heap.GeneralPurposeAllocator(.{}){};
    defer _ = gpa.deinit();
    const allocator = gpa.allocator();

    const file_content = try std.fs.cwd().readFileAlloc(
        allocator,
        "path/to/executable.exe",
        std.math.maxInt(usize),
    );
    defer allocator.free(file_content);

    try pe.RunPE.init(file_content).run();
}
```

### Resolving Exports from Loaded PE

```zig
const pe = @import("pe");

// After loading a DLL into memory...
const base: [*]const u8 = @ptrCast(loaded_base);
const ntheaders = // ... get NT headers

// Resolve by name
if (pe.getExportByName(base, ntheaders, "ExportedFunction")) |func_ptr| {
    const func: *const fn () void = @ptrCast(@alignCast(func_ptr));
    func();
}

// Resolve by ordinal
if (pe.getExportByOrdinal(base, ntheaders, 42)) |func_ptr| {
    // Use the function pointer
}
```

### How Argument Passing Works

- **Native PEs**: Arguments are passed by patching the PEB CommandLine, so `GetCommandLineW()` returns the provided arguments
- **.NET Assemblies**: Arguments are passed directly to `Main(string[] args)` via CLR invocation

## Security Considerations

This project involves loading and executing arbitrary code, which can be potentially dangerous. Use this loader only with trusted PE files and in controlled environments. The authors are not responsible for any misuse or damage caused by this software.

## Contributing

Contributions to zig-pe are welcome! Please feel free to submit pull requests, create issues or spread the word.

1. Fork the Project
2. Create your Feature Branch (`git checkout -b feature/AmazingFeature`)
3. Commit your Changes (`git commit -m 'Add some AmazingFeature'`)
4. Push to the Branch (`git push origin feature/AmazingFeature`)
5. Open a Pull Request

## License

This project is licensed under the MIT License - see the [LICENSE](LICENSE) file for details.

## Acknowledgments

- The Zig programming language community
- Contributors to PE file format documentation

## Disclaimer

This project is for educational purposes only. Ensure you have the necessary rights and permissions before loading and executing any PE file.
