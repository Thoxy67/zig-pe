const std = @import("std");
const win = @cImport(@cInclude("windows.h"));

pub const RunPE = struct {
    buffer: *const []u8,
    header: []const u8,
    addr_alloc: ?*anyopaque,
    addr_array_ptr: [*]u8,
    dosheader: *win.IMAGE_DOS_HEADER,

    /// Initialize the RunPE struct with the given buffer
    pub fn init(buffer: *const []u8) *RunPE {
        var pe = RunPE{
            .buffer = buffer,
            .header = undefined,
            .addr_alloc = undefined,
            .addr_array_ptr = undefined,
            .dosheader = undefined,
        };

        return &pe;
    }

    /// Get the size of the PE headers
    fn get_headers_size(self: *RunPE) usize {
        const e_lfanew: u32 = std.mem.readVarInt(u32, self.buffer.*[60..64], std.builtin.Endian.little);
        return std.mem.readVarInt(u32, self.buffer.*[e_lfanew + 24 + 60 .. e_lfanew + 24 + 60 + 4], std.builtin.Endian.little);
    }

    /// Get the size of the PE image
    fn get_image_size(self: *RunPE) usize {
        const e_lfanew: u32 = std.mem.readVarInt(u32, self.buffer.*[60..64], std.builtin.Endian.little);
        return std.mem.readVarInt(u32, self.buffer.*[e_lfanew + 24 + 56 .. e_lfanew + 24 + 60], std.builtin.Endian.little);
    }

    /// Get the DOS header of the PE file
    pub fn get_dos_header(self: *RunPE) !void {
        self.dosheader = @ptrCast(@alignCast(self.addr_alloc));
        if (self.dosheader.e_magic != 0x5A4D) return error.InvalidDOSHeader;
    }

    /// Get the NT header of the PE file
    pub fn get_nt_header(self: *RunPE) !*win.IMAGE_NT_HEADERS {
        const nt_header: *win.IMAGE_NT_HEADERS = @ptrFromInt(@intFromPtr(self.addr_alloc) + @as(usize, @intCast(self.dosheader.e_lfanew)));
        return if (nt_header.Signature != 0x00004550) error.InvalidNTHeader else nt_header;
    }

    /// Allocate memory for the PE image
    pub fn allocateMemory(self: *RunPE) !void {
        self.addr_alloc = try std.os.windows.VirtualAlloc(null, self.get_image_size(), std.os.windows.MEM_COMMIT | std.os.windows.MEM_RESERVE, std.os.windows.PAGE_READWRITE);
        self.addr_array_ptr = @ptrCast(self.addr_alloc);
    }

    /// Copy the PE headers to the allocated memory
    pub fn copyHeaders(self: *RunPE) !void {
        const header_size = self.get_headers_size();
        @memcpy(self.addr_array_ptr[0..header_size], self.buffer.*[0..header_size]);
        try self.get_dos_header();
    }

    /// Copy the PE headers to the allocated memory
    pub fn copyBuffer(self: *RunPE) !void {
        @memcpy(self.addr_array_ptr, self.buffer[0..self.buffer.len]);
        try self.get_dos_header();
    }

    /// Write each section of the PE file to the allocated memory
    fn write_sections(self: *RunPE, nt_header: *win.IMAGE_NT_HEADERS) !void {
        const section_header_offset = @intFromPtr(self.addr_alloc) + @as(usize, @intCast(self.dosheader.e_lfanew)) + @sizeOf(win.IMAGE_NT_HEADERS);
        for (0..nt_header.FileHeader.NumberOfSections) |count| {
            const nt_section_header: *win.IMAGE_SECTION_HEADER = @ptrFromInt(section_header_offset + (count * @sizeOf(win.IMAGE_SECTION_HEADER)));
            if (nt_section_header.PointerToRawData == 0 or nt_section_header.SizeOfRawData == 0) continue;
            if (nt_section_header.PointerToRawData + nt_section_header.SizeOfRawData > self.buffer.len) return error.SectionOutOfBounds;
            const src = self.buffer.*[nt_section_header.PointerToRawData..][0..nt_section_header.SizeOfRawData];
            @memcpy((self.addr_array_ptr + nt_section_header.VirtualAddress)[0..src.len], src);
        }
    }

    /// Write the import table of the PE file to the allocated memory
    fn write_import_table(self: *RunPE, nt_header: *win.IMAGE_NT_HEADERS) !void {
        const baseptr: [*]u8 = @ptrCast(self.addr_alloc);

        const import_dir = nt_header.OptionalHeader.DataDirectory[win.IMAGE_DIRECTORY_ENTRY_IMPORT];
        if (import_dir.Size == 0) return;

        var importDescriptorPtr: *win.IMAGE_IMPORT_DESCRIPTOR = @ptrFromInt(@intFromPtr(baseptr) + @as(usize, @intCast(import_dir.VirtualAddress)));

        while (importDescriptorPtr.Name != 0 and importDescriptorPtr.FirstThunk != 0) : (importDescriptorPtr = @ptrFromInt(@intFromPtr(importDescriptorPtr) + @sizeOf(win.IMAGE_IMPORT_DESCRIPTOR))) {
            const dllName = try read_string_from_memory(@as([*:0]const u8, @ptrFromInt(@intFromPtr(baseptr) + @as(usize, @intCast(importDescriptorPtr.Name)))));
            const dll_handle: win.HMODULE = win.LoadLibraryA(dllName.ptr);
            if (dll_handle == null) return error.ImportResolutionFailed;
            defer std.os.windows.FreeLibrary(@ptrCast(dll_handle.?));

            var thunk: *align(1) usize = @ptrFromInt(@intFromPtr(baseptr) + importDescriptorPtr.FirstThunk);
            while (thunk.* != 0) : (thunk = @ptrFromInt(@intFromPtr(thunk) + @sizeOf(usize))) {
                if (thunk.* & (1 << 63) != 0) {
                    thunk.* = @intFromPtr(std.os.windows.kernel32.GetProcAddress(@ptrCast(dll_handle), @ptrFromInt(@as(usize, @as(u16, @truncate(thunk.* & 0xFFFF))))));
                } else {
                    thunk.* = @intFromPtr(std.os.windows.kernel32.GetProcAddress(@ptrCast(dll_handle), @ptrCast(&@as(*align(1) const win.IMAGE_IMPORT_BY_NAME, @ptrFromInt(@intFromPtr(baseptr) + thunk.*)).Name[0])));
                }
                if (thunk.* == 0) return error.ImportResolutionFailed;
            }
        }
    }

    /// Fix PE base relocations
    fn fix_base_relocations(self: *RunPE, nt_header: *win.IMAGE_NT_HEADERS) !void {
        const baseptr: [*]u8 = @ptrCast(self.addr_alloc);
        const delta = @intFromPtr(self.addr_alloc) - nt_header.OptionalHeader.ImageBase;

        const reloc_dir = &nt_header.OptionalHeader.DataDirectory[win.IMAGE_DIRECTORY_ENTRY_BASERELOC];
        if (reloc_dir.Size == 0) return;

        var reloc_block: *win.IMAGE_BASE_RELOCATION = @ptrCast(@alignCast(baseptr + reloc_dir.VirtualAddress));

        while (reloc_block.SizeOfBlock != 0) : (reloc_block = @ptrFromInt(@intFromPtr(reloc_block) + reloc_block.SizeOfBlock)) {
            for (@as([*]u16, @ptrCast(@alignCast(@as([*]u8, @ptrCast(reloc_block)) + @sizeOf(win.IMAGE_BASE_RELOCATION))))[0 .. (reloc_block.SizeOfBlock - @sizeOf(win.IMAGE_BASE_RELOCATION)) / 2]) |entry| {
                const t = entry >> 12;
                const offset = entry & 0xFFF;

                switch (t) {
                    win.IMAGE_REL_BASED_HIGHLOW => @as(*u32, @ptrCast(@alignCast(baseptr + reloc_block.VirtualAddress + offset))).* +%= @truncate(delta),
                    win.IMAGE_REL_BASED_DIR64 => @as(*u64, @ptrCast(@alignCast(baseptr + reloc_block.VirtualAddress + offset))).* +%= @as(u64, @bitCast(delta)),
                    win.IMAGE_REL_BASED_ABSOLUTE => {},
                    else => return error.UnsupportedRelocationType,
                }
            }
        }
    }

    /// Change memory protection for PE sections
    fn changeMemoryProtection(self: *RunPE, nt_header: *win.IMAGE_NT_HEADERS) !void {
        var old_protect: std.os.windows.DWORD = undefined;
        const dos_header = @as(*win.IMAGE_DOS_HEADER, @ptrCast(@alignCast(self.addr_alloc)));
        const section_header_offset = @intFromPtr(self.addr_array_ptr) + @as(usize, @intCast(dos_header.e_lfanew)) + @sizeOf(win.IMAGE_NT_HEADERS);
        const baseptr: [*]u8 = @as([*]u8, @ptrCast(self.addr_alloc));
        for (0..nt_header.FileHeader.NumberOfSections) |i| {
            const section: *win.IMAGE_SECTION_HEADER = @ptrFromInt(section_header_offset + (i * @sizeOf(win.IMAGE_SECTION_HEADER)));
            const characteristics = section.Characteristics;
            var new_protect: std.os.windows.DWORD = std.os.windows.PAGE_READONLY;

            if (characteristics & win.IMAGE_SCN_MEM_EXECUTE != 0) new_protect = std.os.windows.PAGE_EXECUTE_READ;
            if (characteristics & win.IMAGE_SCN_MEM_WRITE != 0) new_protect = std.os.windows.PAGE_READWRITE;
            if (characteristics & win.IMAGE_SCN_MEM_EXECUTE != 0 and characteristics & win.IMAGE_SCN_MEM_WRITE != 0) new_protect = std.os.windows.PAGE_EXECUTE_READWRITE;

            try std.os.windows.VirtualProtect(baseptr + section.VirtualAddress, section.Misc.VirtualSize, new_protect, &old_protect);
        }
    }

    /// Execute the loaded PE file
    fn executeLoadedPE(self: *RunPE, nt_header: *win.IMAGE_NT_HEADERS) !void {
        const baseptr: [*]u8 = @as([*]u8, @ptrCast(self.addr_alloc));
        try self.changeMemoryProtection(nt_header);
        const thread_handle = try createAndRunThread(baseptr, nt_header);
        defer std.os.windows.CloseHandle(thread_handle.?);
        _ = try waitForThreadCompletion(thread_handle);
    }

    /// Main function to run the PE file
    pub fn run(self: *RunPE) !void {
        try self.allocateMemory();
        defer _ = std.os.windows.VirtualFree(self.addr_alloc, 0, std.os.windows.MEM_RELEASE);
        try self.copyHeaders();

        const nt_header = try self.get_nt_header();

        if (!is_dotnet_assembly(nt_header)) {
            try self.write_sections(nt_header);
            try self.write_import_table(nt_header);
            try self.fix_base_relocations(nt_header);
            try self.executeLoadedPE(nt_header);
        } else {
            return error.UnsuportedDotNET;
        }
    }
};

/// Check if the PE file is a .NET assembly
fn is_dotnet_assembly(nt_headers: *win.IMAGE_NT_HEADERS) bool {
    const COM_DESCRIPTOR_INDEX = 14; // Index in the DataDirectory array
    const data_directory = &nt_headers.OptionalHeader.DataDirectory[COM_DESCRIPTOR_INDEX];
    return data_directory.VirtualAddress != 0 and data_directory.Size != 0;
}

/// Read a null-terminated string from memory
fn read_string_from_memory(baseptr: [*:0]const u8) ![]const u8 {
    var len: usize = 0;
    while (baseptr[len] != 0) : (len += 1) {
        if (len >= 1024) return error.StringReadError;
    }
    return baseptr[0..len];
}

/// Create and run a new thread for the loaded PE
fn createAndRunThread(addr_array_ptr: [*]u8, nt_header: *win.IMAGE_NT_HEADERS) !win.HANDLE {
    const thread_handle = std.os.windows.kernel32.CreateThread(null, 0, @as(std.os.windows.LPTHREAD_START_ROUTINE, @ptrCast(@alignCast(@as(*const fn () callconv(.C) void, @ptrFromInt(@intFromPtr(addr_array_ptr) + nt_header.OptionalHeader.AddressOfEntryPoint))))), null, 0, null);
    if (thread_handle == null) return error.ThreadCreationFailed;
    return thread_handle.?;
}

/// Wait for the created thread to complete execution
fn waitForThreadCompletion(thread_handle: win.HANDLE) !win.DWORD {
    const wait_result = win.WaitForSingleObject(thread_handle.?, std.os.windows.INFINITE);
    switch (wait_result) {
        win.WAIT_OBJECT_0 => {},
        win.WAIT_TIMEOUT => {},
        win.WAIT_FAILED => return error.WaitFailed,
        else => return error.UnexpectedWaitResult,
    }

    var exit_code: win.DWORD = undefined;
    return if (win.GetExitCodeThread(thread_handle, &exit_code) == 0) error.GetExitCodeFailed else exit_code;
}
