const std = @import("std");
const win = @cImport(@cInclude("windows.h"));
const pe = @import("pe.zig");

var gpa = std.heap.GeneralPurposeAllocator(.{}){};

pub fn main() !void {
    // const file_content = @embedFile("bin\\putty.exe");

    const file_name = "bin/putty.exe";
    const file_content = try std.fs.cwd().readFileAlloc(gpa.allocator(), file_name, std.math.maxInt(usize));

    const header_size = pe.get_headers_size(file_content) catch |e| {
        std.log.err("cannot get header size : {}\n", .{e});
        return e;
    };
    const header = file_content[0..header_size];

    const image_size = pe.get_image_size(file_content) catch |e| {
        std.log.err("cannot get image size : {}\n", .{e});
        return e;
    };

    const addr_alloc: win.LPVOID = std.os.windows.VirtualAlloc(null, image_size, std.os.windows.MEM_COMMIT | std.os.windows.MEM_RESERVE, std.os.windows.PAGE_READWRITE) catch |e| {
        std.log.err("cannot alloc virtual memory {}\n", .{e});
        return e;
    };

    const addr_array_ptr: [*]u8 = @ptrFromInt(@intFromPtr(addr_alloc));

    @memcpy(addr_array_ptr, header);

    const dosheader: *const win.IMAGE_DOS_HEADER = @ptrCast(@alignCast(addr_alloc));
    //std.debug.print("{any} \n", .{dosheader});

    const lp_nt_header: *const win.IMAGE_NT_HEADERS = pe.get_nt_header64(addr_alloc, dosheader);
    //std.debug.print("{any} \n", .{lp_nt_header});

    pe.write_sections(addr_alloc, file_content, dosheader, lp_nt_header);

    pe.write_import_table(addr_alloc, lp_nt_header);

    // fix_base_relocations(baseptr, nt_header);

    //std.debug.print("0x{x}\n", .{@intFromPtr(addr_array_ptr)});

    //while (true) {}

    fix_base_relocations(addr_alloc, lp_nt_header);

    //pe.execute_image(addr_array_ptr, lp_nt_header);
}

// FIXME
fn fix_base_relocations(baseptr: ?*const anyopaque, nt_header: *const win.IMAGE_NT_HEADERS) void {
    const optionalHeader = nt_header.*.OptionalHeader;
    const relocationDirRVA: u32 = optionalHeader.DataDirectory[win.IMAGE_DIRECTORY_ENTRY_BASERELOC].VirtualAddress;

    var base_ptr: usize = @intFromPtr(@as(*win.IMAGE_BASE_RELOCATION, @ptrFromInt(@intFromPtr(baseptr) + relocationDirRVA)));

    const relocationDirSize: u32 = optionalHeader.DataDirectory[win.IMAGE_DIRECTORY_ENTRY_BASERELOC].Size;

    std.debug.print("Optional Header Base: {x}\n", .{optionalHeader.ImageBase});
    std.debug.print("Relocation RVA: {x}, Size: {x}, Base: {x}\n", .{ relocationDirRVA, relocationDirSize, base_ptr });

    var base = @as(*win.IMAGE_BASE_RELOCATION, @ptrFromInt(base_ptr));

    while (base.*.SizeOfBlock != 0) {
        if (relocationDirSize == 0) {
            break;
        }
        const entries_count: u32 = (base.*.SizeOfBlock - 8) / 2;

        std.debug.print("Entries Count: {x}\n", .{entries_count});

        // for (0..entries_count) |i| {
        //     const offset_ptr: [*]u8 = @ptrFromInt((base_ptr + 8) + (i * 2));
        //     const offset: i16 = std.mem.readVarInt(i16, offset_ptr[0..2], std.builtin.Endian.little);
        //     std.debug.print("offset: {x}\n", .{offset});
        // }

        base_ptr += relocationDirSize;
        base = @as(*win.IMAGE_BASE_RELOCATION, @ptrFromInt(base_ptr));
    }
    while (true) {}
}

test "simple test" {}

// BOOL FixRelocs(void *base, void *rBase, IMAGE_NT_HEADERS *ntHd, IMAGE_BASE_RELOCATION *reloc,unsigned int size) {
//     unsigned long ImageBase = ntHd->OptionalHeader.ImageBase;
//     unsigned int nBytes = 0;
//     unsigned long delta = MakeDelta(unsigned long, rBase, ImageBase);
//     unsigned long *locBase;
// unsigned int numRelocs;
// unsigned short *locData;
// unsigned int i;

// while(1) {
//   locBase =
//      (unsigned long *)GetPtrFromRVA((DWORD)(reloc->VirtualAddress), ntHd, (PBYTE)base);
//   numRelocs = (reloc->SizeOfBlock - sizeof(IMAGE_BASE_RELOCATION)) / sizeof(WORD);

//   if(nBytes >= size) break;

//   locData = MakePtr(unsigned short *, reloc, sizeof(IMAGE_BASE_RELOCATION));
//   for(i = 0; i < numRelocs; i++) {
//      if(((*locData >> 12) == IMAGE_REL_BASED_HIGHLOW))
//          *MakePtr(unsigned long *, locBase, (*locData & 0x0FFF)) += delta;
//      locData++;
//   }

//   nBytes += reloc->SizeOfBlock;
//   reloc = (IMAGE_BASE_RELOCATION *)locData;
//    }

//    return TRUE;

// }
