const std = @import("std");
const win = @cImport(@cInclude("windows.h"));
const pe = @import("pe.zig");

var gpa = std.heap.GeneralPurposeAllocator(.{}){};

pub fn main() !void {
    const file_name = "bin/putty.exe";
    const file_content = try std.fs.cwd().readFileAlloc(gpa.allocator(), file_name, std.math.maxInt(usize));

    const header_size = pe.get_headers_size(file_content) catch {
        std.debug.print("cannot get header size\n", .{});
        return;
    };

    const image_size = pe.get_image_size(file_content) catch {
        std.debug.print("cannot get image size\n", .{});
        return;
    };

    const addr: win.LPVOID = std.os.windows.VirtualAlloc(null, image_size, std.os.windows.MEM_COMMIT, std.os.windows.PAGE_READWRITE) catch {
        std.debug.print("cannot alloc virtual memory\n", .{});
        return;
    };

    const pHandle = win.OpenProcess(win.PROCESS_ALL_ACCESS, std.os.windows.FALSE, win.GetCurrentProcessId());
    if (pHandle == null) {
        std.debug.print("cannot open current process\n", .{});
        return;
    }

    var _bytesWritten: win.SIZE_T = undefined;
    const header = file_content[0..header_size];
    if (win.WriteProcessMemory(pHandle, addr, @ptrCast(header.ptr), header.len, &_bytesWritten) == win.FALSE) {
        std.debug.print("cannot write to process memory\n", .{});
        return;
    }

    const dosheader: *win.IMAGE_DOS_HEADER = @ptrCast(@alignCast(addr));

    //std.debug.print("{any} \n", .{dosheader});

    const lp_nt_header = pe.get_nt_header64(addr, dosheader);

    //std.debug.print("{any} \n", .{lp_nt_header});

    write_sections(addr, file_content, dosheader, lp_nt_header);

    //std.debug.print("{any} \n", .{lp_nt_header});

}

fn write_sections(baseptr: win.LPVOID, buffer: []u8, dos_header: *win.IMAGE_DOS_HEADER, nt_header: *win.IMAGE_NT_HEADERS) void {
    const number_of_sections = nt_header.FileHeader.NumberOfSections;

    const e_lfanew: usize = @intCast(dos_header.e_lfanew);

    const nt_section_header: *win.IMAGE_SECTION_HEADER = @ptrFromInt(@intFromPtr(baseptr) + e_lfanew + @sizeOf(win.IMAGE_NT_HEADERS));

    std.debug.print("{s} \n", .{nt_section_header.Name});

    for (0..number_of_sections) |n| {
        const section_data = buffer[(nt_section_header.PointerToRawData + (@sizeOf(win.IMAGE_SECTION_HEADER) * n))..(nt_section_header.PointerToRawData + nt_section_header.SizeOfRawData)];

        const VirtualAddress: usize = @intCast(nt_section_header.VirtualAddress);

        const a: [*]u8 = @ptrFromInt(@intFromPtr(baseptr) + VirtualAddress);
        @memcpy(a, section_data);

        const b: *win.IMAGE_SECTION_HEADER = @ptrCast(@alignCast(a));

        std.debug.print("{} = {s} \n", .{ n, b.Name });
    }

    //std.log.debug("{s}\n", nt_section_header.Name);
}

test "simple test" {}
