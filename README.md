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

### Export Table Resolution

Utility functions for resolving exports from a loaded PE image:

- `getExportByName(base, ntheaders, name)` — resolve by name
- `getExportByOrdinal(base, ntheaders, ordinal)` — resolve by ordinal

Handles forwarded export detection (returns null for forwarded exports).

### Compatibility

- [x] Native compiled binary execution (x86, x86_64, ARM, ARM64)
- [x] .NET compiled binary execution via CLR hosting
- [x] Command-line argument passing to .NET `Main(string[] args)`

## Prerequisites

- Zig compiler (latest version recommended)
- Windows OS (the project uses Windows-specific APIs)

## Building the Project

1. Clone the repository:
   ```
   git clone https://github.com/yourusername/zig-pe.git
   cd zig-pe
   ```

2. Build the project:
   ```
   zig build
   ```

## Usage

Here's a basic example of how to use the zig-pe loader:

```zig
const std = @import("std");
const pe = @import("pe.zig");

pub fn main() !void {

    // Use local PE
    // var gpa = std.heap.GeneralPurposeAllocator(.{}){};
    // defer _ = gpa.deinit();
    // const allocator = gpa.allocator();
    // const file_name = "src/bin/putty.exe";
    // const file_content = try std.fs.cwd().readFileAlloc(allocator, file_name, std.math.maxInt(usize));
    // defer allocator.free(file_content);

    // Use embed PE
    try pe.RunPE.init(@embedFile("bin/putty.exe")).run();
}

```

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
