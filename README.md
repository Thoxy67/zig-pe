# zig-pe

Simple RunPE loader written in zig.

## Information

For now this not work. I need to fix base relocation but I'm little bit tired to code in Zig.

Zig is a wonderful language but it seems to need a little bit more work.
Some things are really weird in Zig my write import library are 40 bytes to far from where it need to grab dll names and function.
My NT header has good value but some are not.

I will try to fix it later when my motivation come back.

- [x] - Get DOS_IMAGE_HEADER
- [x] - Get NT_IMAGE_HEADER
- [x] - Get DOS_IMAGE_HEADER size
- [x] - Get NT_IMAGE_HEADER size
- [x] - Alloc memory to bind PE image
- [x] - @memcpy the PE to the allocated memory pointer
- [x] - Write section to header
- [x] - Write import table (import dll's and functions)
- [x] - Fix base relocation (really painfull)
- [x] - Call the entrypoint as function (logic seems ok but I can't test without fixing base relocation)

## License

This project is licensed under the [MIT License](LICENSE).
