# zig-pe

A simple RunPE loader written in Zig, designed to load and execute Portable Executable (PE) files in memory.

## Overview

This project implements a RunPE loader in Zig, allowing for the dynamic loading and execution of PE files directly from memory. It's designed to work with native compiled binaries and provides a set of functions to handle various aspects of PE file manipulation.

## Features

- [x] Parse and retrieve DOS_IMAGE_HEADER
- [x] Parse and retrieve NT_IMAGE_HEADER
- [x] Calculate DOS_IMAGE_HEADER size
- [x] Calculate NT_IMAGE_HEADER size
- [x] Allocate memory for PE image binding
- [x] Copy PE file contents to allocated memory
- [x] Write sections to header
- [x] Handle import table (load required DLLs and resolve functions)
- [x] Fix base relocations
- [x] Change Memory Protection
- [x] Execute the PE file's entry point

## Compatibility

- [x] Native compiled binary execution
- [ ] .NET compiled binary execution (not yet implemented)

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
