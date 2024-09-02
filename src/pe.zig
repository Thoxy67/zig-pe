const std = @import("std");
const utils = @import("utils.zig");
const win = @cImport(@cInclude("windows.h"));

pub const RunPE = struct {
    buffer: []const u8,
    addr_alloc: ?*anyopaque,
    addr_array_ptr: [*]u8,
    dosheader: *win.IMAGE_DOS_HEADER,
    ntheaders: *win.IMAGE_NT_HEADERS,
    platform: ?u32,
    is_32bit: bool,

    /// Initialize the RunPE struct with the given buffer
    pub fn init(buffer: []const u8) *RunPE {
        var pe = RunPE{
            .buffer = buffer,
            .addr_alloc = undefined,
            .addr_array_ptr = undefined,
            .dosheader = undefined,
            .ntheaders = undefined,
            .platform = null,
            .is_32bit = false,
        };

        return &pe;
    }

    /// Get the size of the PE headers
    fn get_headers_size(self: *RunPE) usize {
        const e_lfanew: u32 = std.mem.readVarInt(u32, self.buffer[60..64], std.builtin.Endian.little);
        return std.mem.readVarInt(u32, self.buffer[e_lfanew + 24 + 60 .. e_lfanew + 24 + 60 + 4], std.builtin.Endian.little);
    }

    /// Get the size of the PE image
    fn get_image_size(self: *RunPE) usize {
        const e_lfanew: u32 = std.mem.readVarInt(u32, self.buffer[60..64], std.builtin.Endian.little);
        return std.mem.readVarInt(u32, self.buffer[e_lfanew + 24 + 56 .. e_lfanew + 24 + 60], std.builtin.Endian.little);
    }

    /// Get the DOS header of the PE file
    pub fn get_dos_header(self: *RunPE) !void {
        self.dosheader = @ptrCast(@alignCast(self.addr_array_ptr));
        if (self.dosheader.e_magic != 0x5A4D) return error.InvalidDOSHeader;
    }

    /// Get the NT header of the PE file
    pub fn get_nt_header(self: *RunPE) !void {
        self.platform = try utils.detect_platform(self.buffer);
        if (self.platform == 32) {
            self.is_32bit = true;
        }

        self.ntheaders = @ptrFromInt(@intFromPtr(self.addr_array_ptr) + @as(usize, @intCast(self.dosheader.e_lfanew)));

        if (self.ntheaders.Signature != 0x00004550) return error.InvalidNTHeader;
    }

    /// Allocate memory for the PE image
    pub fn allocateMemory(self: *RunPE) !void {
        self.addr_alloc = try std.os.windows.VirtualAlloc(null, self.get_image_size(), std.os.windows.MEM_COMMIT | std.os.windows.MEM_RESERVE, std.os.windows.PAGE_READWRITE);
        self.addr_array_ptr = @ptrCast(self.addr_alloc);
    }

    /// Copy the PE headers to the allocated memory
    pub fn copyHeaders(self: *RunPE) !void {
        const header_size = self.get_headers_size();
        @memcpy(self.addr_array_ptr[0..header_size], self.buffer[0..header_size]);
        try self.get_dos_header();
    }

    /// Write each section of the PE file to the allocated memory
    fn write_sections(self: *RunPE) !void {
        const section_header_offset = @intFromPtr(self.addr_array_ptr) + @as(usize, @intCast(self.dosheader.e_lfanew)) + @sizeOf(win.IMAGE_NT_HEADERS);
        for (0..self.ntheaders.FileHeader.NumberOfSections) |count| {
            const nt_section_header: *win.IMAGE_SECTION_HEADER = @ptrFromInt(section_header_offset + (count * @sizeOf(win.IMAGE_SECTION_HEADER)));
            if (nt_section_header.PointerToRawData == 0 or nt_section_header.SizeOfRawData == 0) continue;
            if (nt_section_header.PointerToRawData + nt_section_header.SizeOfRawData > self.buffer.len) return error.SectionOutOfBounds;
            const src = self.buffer[nt_section_header.PointerToRawData..][0..nt_section_header.SizeOfRawData];
            @memcpy((self.addr_array_ptr + nt_section_header.VirtualAddress)[0..src.len], src);
        }
    }

    /// Write the import table of the PE file to the allocated memory
    fn write_import_table(self: *RunPE) !void {
        if (self.ntheaders.OptionalHeader.DataDirectory[win.IMAGE_DIRECTORY_ENTRY_IMPORT].Size == 0) return;
        var importDescriptorPtr: *win.IMAGE_IMPORT_DESCRIPTOR = @ptrFromInt(@intFromPtr(self.addr_array_ptr) + @as(usize, @intCast(self.ntheaders.OptionalHeader.DataDirectory[win.IMAGE_DIRECTORY_ENTRY_IMPORT].VirtualAddress)));
        while (importDescriptorPtr.Name != 0 and importDescriptorPtr.FirstThunk != 0) : (importDescriptorPtr = @ptrFromInt(@intFromPtr(importDescriptorPtr) + @sizeOf(win.IMAGE_IMPORT_DESCRIPTOR))) {
            const dll_handle: win.HMODULE = win.LoadLibraryA(std.mem.sliceTo(@as([*:0]const u8, @ptrFromInt(@intFromPtr(self.addr_array_ptr) + @as(usize, @intCast(importDescriptorPtr.Name)))), 0).ptr) orelse return error.ImportResolutionFailed;
            defer std.os.windows.FreeLibrary(@ptrCast(dll_handle.?));

            var thunk: *align(1) usize = @ptrFromInt(@intFromPtr(self.addr_array_ptr) + importDescriptorPtr.FirstThunk);
            while (thunk.* != 0) : (thunk = @ptrFromInt(@intFromPtr(thunk) + @sizeOf(usize))) {
                thunk.* = if (thunk.* & (1 << 63) != 0)
                    @intFromPtr(std.os.windows.kernel32.GetProcAddress(@ptrCast(dll_handle), @ptrFromInt(@as(usize, @as(u16, @truncate(thunk.* & 0xFFFF))))))
                else
                    @intFromPtr(std.os.windows.kernel32.GetProcAddress(@ptrCast(dll_handle), @ptrCast(&@as(*align(1) const win.IMAGE_IMPORT_BY_NAME, @ptrFromInt(@intFromPtr(self.addr_array_ptr) + thunk.*)).Name[0])));

                if (thunk.* == 0) return error.ImportResolutionFailed;
            }
        }
    }

    /// Fix PE base relocations
    fn fix_base_relocations(self: *RunPE) !void {
        if (self.ntheaders.OptionalHeader.DataDirectory[win.IMAGE_DIRECTORY_ENTRY_BASERELOC].Size == 0) return;
        var reloc_block: *win.IMAGE_BASE_RELOCATION = @ptrCast(@alignCast(self.addr_array_ptr + self.ntheaders.OptionalHeader.DataDirectory[win.IMAGE_DIRECTORY_ENTRY_BASERELOC].VirtualAddress));
        while (reloc_block.SizeOfBlock != 0) : (reloc_block = @ptrFromInt(@intFromPtr(reloc_block) + reloc_block.SizeOfBlock)) {
            for (@as([*]u16, @ptrCast(@alignCast(@as([*]u8, @ptrCast(reloc_block)) + @sizeOf(win.IMAGE_BASE_RELOCATION))))[0 .. (reloc_block.SizeOfBlock - @sizeOf(win.IMAGE_BASE_RELOCATION)) / 2]) |entry| {
                const offset = entry & 0xFFF;
                switch (entry >> 12) {
                    win.IMAGE_REL_BASED_HIGHLOW => @as(*u32, @ptrCast(@alignCast(self.addr_array_ptr + reloc_block.VirtualAddress + offset))).* +%= @truncate(@intFromPtr(self.addr_array_ptr) - self.ntheaders.OptionalHeader.ImageBase),
                    win.IMAGE_REL_BASED_DIR64 => @as(*usize, @ptrCast(@alignCast(self.addr_array_ptr + reloc_block.VirtualAddress + offset))).* +%= @as(usize, @bitCast(@intFromPtr(self.addr_array_ptr) - self.ntheaders.OptionalHeader.ImageBase)),
                    win.IMAGE_REL_BASED_ABSOLUTE => {},
                    else => return error.UnsupportedRelocationType,
                }
            }
        }
    }

    /// Change memory protection for PE sections
    fn changeMemoryProtection(self: *RunPE) !void {
        var old_protect: std.os.windows.DWORD = undefined;
        const dos_header = @as(*win.IMAGE_DOS_HEADER, @ptrCast(@alignCast(self.addr_array_ptr)));
        const section_header_offset = @intFromPtr(self.addr_array_ptr) + @as(usize, @intCast(dos_header.e_lfanew)) + @sizeOf(win.IMAGE_NT_HEADERS);
        for (0..self.ntheaders.FileHeader.NumberOfSections) |i| {
            const section: *win.IMAGE_SECTION_HEADER = @ptrFromInt(section_header_offset + (i * @sizeOf(win.IMAGE_SECTION_HEADER)));
            var new_protect: std.os.windows.DWORD = std.os.windows.PAGE_READONLY;
            if (section.Characteristics & win.IMAGE_SCN_MEM_EXECUTE != 0) new_protect = std.os.windows.PAGE_EXECUTE_READ;
            if (section.Characteristics & win.IMAGE_SCN_MEM_WRITE != 0) new_protect = std.os.windows.PAGE_READWRITE;
            if (section.Characteristics & win.IMAGE_SCN_MEM_EXECUTE != 0 and section.Characteristics & win.IMAGE_SCN_MEM_WRITE != 0) new_protect = std.os.windows.PAGE_EXECUTE_READWRITE;
            try std.os.windows.VirtualProtect(self.addr_array_ptr + section.VirtualAddress, section.Misc.VirtualSize, new_protect, &old_protect);
        }
    }

    /// Create and run a new thread for the loaded PE
    fn createAndRunThread(self: *RunPE, nt_header: *win.IMAGE_NT_HEADERS) !win.HANDLE {
        const thread_handle = std.os.windows.kernel32.CreateThread(null, 0, @as(std.os.windows.LPTHREAD_START_ROUTINE, @ptrCast(@alignCast(@as(*const fn () callconv(.C) void, @ptrFromInt(@intFromPtr(self.addr_array_ptr) + nt_header.OptionalHeader.AddressOfEntryPoint))))), null, 0, null);
        if (thread_handle == null) return error.ThreadCreationFailed;
        return thread_handle.?;
    }

    /// Execute the loaded PE file
    fn executeLoadedPE(
        self: *RunPE,
    ) !void {
        const thread_handle = try self.createAndRunThread(self.ntheaders);
        defer std.os.windows.CloseHandle(thread_handle.?);
        _ = try utils.waitForThreadCompletion(thread_handle);
    }

    /// Main function to run the PE file
    pub fn run(self: *RunPE) !void {
        try self.allocateMemory();
        defer _ = std.os.windows.VirtualFree(self.addr_alloc, 0, std.os.windows.MEM_RELEASE);
        try self.copyHeaders();

        try self.get_nt_header();

        if (!utils.is_dotnet_assembly(self.ntheaders)) {
            try self.write_sections();
            try self.write_import_table();
            try self.fix_base_relocations();
            try self.changeMemoryProtection();
            try self.executeLoadedPE();
        } else {
            return error.UnsuportedDotNET;
        }
    }
};
