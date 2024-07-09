# zig-pe

Simple RunPE loader written in zig.

## Information

- [x] - Get DOS_IMAGE_HEADER
- [x] - Get NT_IMAGE_HEADER
- [x] - Get DOS_IMAGE_HEADER size
- [x] - Get NT_IMAGE_HEADER size
- [x] - Alloc memory to bind PE image
- [x] - @memcpy the PE to the allocated memory pointer
- [x] - Write section to header
- [x] - Write import table (import dll's and functions)
- [x] - Fix base relocation
- [x] - Call the entrypoint as function


- [x] - Native compiled binary launch
- [ ] - .NET compiled binary launch


## License

This project is licensed under the [MIT License](LICENSE).
