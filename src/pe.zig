const std = @import("std");
const utils = @import("utils.zig");
const dotnet = @import("dotnet.zig");
const win = @cImport(@cInclude("windows.h"));
const builtin = @import("builtin");

// ============================================================================
// Zig-native PE optional header structs
// ============================================================================
// We define these ourselves because the C import's IMAGE_NT_HEADERS is always
// the host-native variant (64-bit on x64 builds). To load PE32 files on a
// PE32+ host (for validation/parsing), we need both layouts available.

pub const IMAGE_DATA_DIRECTORY = extern struct {
    VirtualAddress: u32,
    Size: u32,
};

pub const IMAGE_OPTIONAL_HEADER32 = extern struct {
    Magic: u16,
    MajorLinkerVersion: u8,
    MinorLinkerVersion: u8,
    SizeOfCode: u32,
    SizeOfInitializedData: u32,
    SizeOfUninitializedData: u32,
    AddressOfEntryPoint: u32,
    BaseOfCode: u32,
    BaseOfData: u32, // only in PE32
    ImageBase: u32, // 32-bit
    SectionAlignment: u32,
    FileAlignment: u32,
    MajorOperatingSystemVersion: u16,
    MinorOperatingSystemVersion: u16,
    MajorImageVersion: u16,
    MinorImageVersion: u16,
    MajorSubsystemVersion: u16,
    MinorSubsystemVersion: u16,
    Win32VersionValue: u32,
    SizeOfImage: u32,
    SizeOfHeaders: u32,
    CheckSum: u32,
    Subsystem: u16,
    DllCharacteristics: u16,
    SizeOfStackReserve: u32, // 32-bit
    SizeOfStackCommit: u32, // 32-bit
    SizeOfHeapReserve: u32, // 32-bit
    SizeOfHeapCommit: u32, // 32-bit
    LoaderFlags: u32,
    NumberOfRvaAndSizes: u32,
    DataDirectory: [16]IMAGE_DATA_DIRECTORY,
};

pub const IMAGE_OPTIONAL_HEADER64 = extern struct {
    Magic: u16,
    MajorLinkerVersion: u8,
    MinorLinkerVersion: u8,
    SizeOfCode: u32,
    SizeOfInitializedData: u32,
    SizeOfUninitializedData: u32,
    AddressOfEntryPoint: u32,
    BaseOfCode: u32,
    // no BaseOfData in PE32+
    ImageBase: u64, // 64-bit
    SectionAlignment: u32,
    FileAlignment: u32,
    MajorOperatingSystemVersion: u16,
    MinorOperatingSystemVersion: u16,
    MajorImageVersion: u16,
    MinorImageVersion: u16,
    MajorSubsystemVersion: u16,
    MinorSubsystemVersion: u16,
    Win32VersionValue: u32,
    SizeOfImage: u32,
    SizeOfHeaders: u32,
    CheckSum: u32,
    Subsystem: u16,
    DllCharacteristics: u16,
    SizeOfStackReserve: u64, // 64-bit
    SizeOfStackCommit: u64, // 64-bit
    SizeOfHeapReserve: u64, // 64-bit
    SizeOfHeapCommit: u64, // 64-bit
    LoaderFlags: u32,
    NumberOfRvaAndSizes: u32,
    DataDirectory: [16]IMAGE_DATA_DIRECTORY,
};

pub const IMAGE_NT_HEADERS32 = extern struct {
    Signature: u32,
    FileHeader: win.IMAGE_FILE_HEADER,
    OptionalHeader: IMAGE_OPTIONAL_HEADER32,
};

pub const IMAGE_NT_HEADERS64 = extern struct {
    Signature: u32,
    FileHeader: win.IMAGE_FILE_HEADER,
    OptionalHeader: IMAGE_OPTIONAL_HEADER64,
};

/// Tagged union representing either PE32 or PE32+ NT headers
pub const NtHeaders = union(enum) {
    pe32: *IMAGE_NT_HEADERS32,
    pe64: *IMAGE_NT_HEADERS64,

    pub fn signature(self: NtHeaders) u32 {
        return switch (self) {
            .pe32 => |h| h.Signature,
            .pe64 => |h| h.Signature,
        };
    }

    pub fn fileHeader(self: NtHeaders) *win.IMAGE_FILE_HEADER {
        return switch (self) {
            .pe32 => |h| &h.FileHeader,
            .pe64 => |h| &h.FileHeader,
        };
    }

    pub fn numberOfSections(self: NtHeaders) u16 {
        return self.fileHeader().NumberOfSections;
    }

    pub fn sizeOfOptionalHeader(self: NtHeaders) u16 {
        return self.fileHeader().SizeOfOptionalHeader;
    }

    pub fn addressOfEntryPoint(self: NtHeaders) u32 {
        return switch (self) {
            .pe32 => |h| h.OptionalHeader.AddressOfEntryPoint,
            .pe64 => |h| h.OptionalHeader.AddressOfEntryPoint,
        };
    }

    pub fn imageBase(self: NtHeaders) u64 {
        return switch (self) {
            .pe32 => |h| @as(u64, h.OptionalHeader.ImageBase),
            .pe64 => |h| h.OptionalHeader.ImageBase,
        };
    }

    pub fn dataDirectory(self: NtHeaders) []IMAGE_DATA_DIRECTORY {
        return switch (self) {
            .pe32 => |h| &h.OptionalHeader.DataDirectory,
            .pe64 => |h| &h.OptionalHeader.DataDirectory,
        };
    }

    pub fn is32(self: NtHeaders) bool {
        return self == .pe32;
    }
};

// ============================================================================
// Constants
// ============================================================================
const IMAGE_DIRECTORY_ENTRY_EXPORT: usize = 0;
const IMAGE_DIRECTORY_ENTRY_IMPORT: usize = 1;
const IMAGE_DIRECTORY_ENTRY_EXCEPTION: usize = 3;
const IMAGE_DIRECTORY_ENTRY_BASERELOC: usize = 5;
const IMAGE_DIRECTORY_ENTRY_TLS: usize = 9;
const IMAGE_DIRECTORY_ENTRY_DELAY_IMPORT: usize = 13;
const IMAGE_DIRECTORY_ENTRY_COM_DESCRIPTOR: usize = 14;

const DLL_PROCESS_ATTACH: u32 = 1;

const IMAGE_DELAYLOAD_DESCRIPTOR = extern struct {
    Attributes: u32,
    DllNameRVA: u32,
    ModuleHandleRVA: u32,
    ImportAddressTableRVA: u32,
    ImportNameTableRVA: u32,
    BoundImportAddressTableRVA: u32,
    UnloadInformationTableRVA: u32,
    TimeDateStamp: u32,
};

const RUNTIME_FUNCTION = extern struct {
    BeginAddress: u32,
    EndAddress: u32,
    UnwindData: u32,
};

pub const IMAGE_EXPORT_DIRECTORY = extern struct {
    Characteristics: u32,
    TimeDateStamp: u32,
    MajorVersion: u16,
    MinorVersion: u16,
    Name: u32,
    Base: u32,
    NumberOfFunctions: u32,
    NumberOfNames: u32,
    AddressOfFunctions: u32,
    AddressOfNames: u32,
    AddressOfNameOrdinals: u32,
};

const IMAGE_REL_BASED_ABSOLUTE: u4 = 0;
const IMAGE_REL_BASED_HIGHLOW: u4 = 3;
const IMAGE_REL_BASED_ARM_MOV32: u4 = 5;
const IMAGE_REL_BASED_THUMB_MOV32: u4 = 7;
const IMAGE_REL_BASED_DIR64: u4 = 10;

const PE32_MAGIC: u16 = 0x10b;
const PE32PLUS_MAGIC: u16 = 0x20b;

// ============================================================================
// ARM relocation helpers
// ============================================================================

/// Extract 32-bit value from ARM MOVW+MOVT instruction pair.
fn armMov32Extract(addr: [*]const u8) u32 {
    const movw = std.mem.readInt(u32, addr[0..4], .little);
    const movt = std.mem.readInt(u32, addr[4..8], .little);
    const low: u32 = ((movw >> 4) & 0xF000) | (movw & 0xFFF);
    const high: u32 = ((movt >> 4) & 0xF000) | (movt & 0xFFF);
    return (high << 16) | low;
}

/// Encode 32-bit value back into ARM MOVW+MOVT instruction pair.
fn armMov32Encode(addr: [*]u8, value: u32) void {
    const low = value & 0xFFFF;
    const high = value >> 16;

    var movw = std.mem.readInt(u32, addr[0..4], .little);
    movw = (movw & 0xFFF0_F000) | ((low & 0xF000) << 4) | (low & 0xFFF);
    std.mem.writeInt(u32, addr[0..4], movw, .little);

    var movt = std.mem.readInt(u32, addr[4..8], .little);
    movt = (movt & 0xFFF0_F000) | ((high & 0xF000) << 4) | (high & 0xFFF);
    std.mem.writeInt(u32, addr[4..8], movt, .little);
}

/// Extract 32-bit value from Thumb-2 MOVW+MOVT instruction pair.
fn thumbMov32Extract(addr: [*]const u8) u32 {
    const hw0: u32 = std.mem.readInt(u16, addr[0..2], .little);
    const hw1: u32 = std.mem.readInt(u16, addr[2..4], .little);
    const hw2: u32 = std.mem.readInt(u16, addr[4..6], .little);
    const hw3: u32 = std.mem.readInt(u16, addr[6..8], .little);

    const low = ((hw0 & 0xF) << 12) |
        (((hw0 >> 10) & 1) << 11) |
        (((hw1 >> 12) & 0x7) << 8) |
        (hw1 & 0xFF);

    const high = ((hw2 & 0xF) << 12) |
        (((hw2 >> 10) & 1) << 11) |
        (((hw3 >> 12) & 0x7) << 8) |
        (hw3 & 0xFF);

    return (high << 16) | low;
}

/// Encode 32-bit value back into Thumb-2 MOVW+MOVT instruction pair.
fn thumbMov32Encode(addr: [*]u8, value: u32) void {
    const low = value & 0xFFFF;
    const high = value >> 16;

    var hw0: u16 = std.mem.readInt(u16, addr[0..2], .little);
    var hw1: u16 = std.mem.readInt(u16, addr[2..4], .little);
    hw0 = @truncate((@as(u32, hw0) & 0xFBF0) | ((low >> 12) & 0xF) | (((low >> 11) & 1) << 10));
    hw1 = @truncate((@as(u32, hw1) & 0x8F00) | (((low >> 8) & 0x7) << 12) | (low & 0xFF));
    std.mem.writeInt(u16, addr[0..2], hw0, .little);
    std.mem.writeInt(u16, addr[2..4], hw1, .little);

    var hw2: u16 = std.mem.readInt(u16, addr[4..6], .little);
    var hw3: u16 = std.mem.readInt(u16, addr[6..8], .little);
    hw2 = @truncate((@as(u32, hw2) & 0xFBF0) | ((high >> 12) & 0xF) | (((high >> 11) & 1) << 10));
    hw3 = @truncate((@as(u32, hw3) & 0x8F00) | (((high >> 8) & 0x7) << 12) | (high & 0xFF));
    std.mem.writeInt(u16, addr[4..6], hw2, .little);
    std.mem.writeInt(u16, addr[6..8], hw3, .little);
}

// ============================================================================
// RunPE
// ============================================================================

pub const RunPE = struct {
    buffer: []const u8,
    addr_alloc: ?*anyopaque,
    addr_array_ptr: [*]u8,
    dosheader: *win.IMAGE_DOS_HEADER,
    ntheaders: NtHeaders,
    is_32bit: bool,
    exception_table_ptr: ?*const RUNTIME_FUNCTION,

    /// Initialize the RunPE struct with the given buffer
    pub fn init(buffer: []const u8) RunPE {
        return RunPE{
            .buffer = buffer,
            .addr_alloc = null,
            .addr_array_ptr = undefined,
            .dosheader = undefined,
            .ntheaders = undefined,
            .is_32bit = false,
            .exception_table_ptr = null,
        };
    }

    /// Read SizeOfHeaders from the raw buffer (works before allocation).
    /// Layout: e_lfanew + 24 + offset_of(SizeOfHeaders) in OptionalHeader.
    /// SizeOfHeaders is at the same offset (60) in both PE32 and PE32+.
    fn get_headers_size(self: *RunPE) usize {
        const e_lfanew: u32 = std.mem.readInt(u32, self.buffer[60..64], .little);
        // Offset 60 into OptionalHeader = SizeOfHeaders for both PE32 and PE32+
        const opt_start = e_lfanew + 24; // skip Signature(4) + FileHeader(20)
        return std.mem.readInt(u32, self.buffer[opt_start + 60 ..][0..4], .little);
    }

    /// Read SizeOfImage from the raw buffer.
    /// SizeOfImage is at offset 56 in OptionalHeader for both PE32 and PE32+.
    fn get_image_size(self: *RunPE) usize {
        const e_lfanew: u32 = std.mem.readInt(u32, self.buffer[60..64], .little);
        const opt_start = e_lfanew + 24;
        return std.mem.readInt(u32, self.buffer[opt_start + 56 ..][0..4], .little);
    }

    /// Get the DOS header of the PE file from allocated memory
    pub fn get_dos_header(self: *RunPE) !void {
        self.dosheader = @ptrCast(@alignCast(self.addr_array_ptr));
        if (self.dosheader.e_magic != 0x5A4D) return error.InvalidDOSHeader;
    }

    /// Get the NT header, detecting PE32 vs PE32+ at runtime
    pub fn get_nt_header(self: *RunPE) !void {
        const platform = try utils.detect_platform(self.buffer);
        self.is_32bit = (platform == 32);

        const nt_addr = @intFromPtr(self.addr_array_ptr) + @as(usize, @intCast(self.dosheader.e_lfanew));

        if (self.is_32bit) {
            const h: *IMAGE_NT_HEADERS32 = @ptrFromInt(nt_addr);
            if (h.Signature != 0x00004550) return error.InvalidNTHeader;
            if (h.OptionalHeader.Magic != PE32_MAGIC) return error.InvalidOptionalHeaderMagic;
            self.ntheaders = .{ .pe32 = h };
        } else {
            const h: *IMAGE_NT_HEADERS64 = @ptrFromInt(nt_addr);
            if (h.Signature != 0x00004550) return error.InvalidNTHeader;
            if (h.OptionalHeader.Magic != PE32PLUS_MAGIC) return error.InvalidOptionalHeaderMagic;
            self.ntheaders = .{ .pe64 = h };
        }
    }

    /// Validate that the PE bitness matches the host loader architecture
    fn validateArchitecture(self: *RunPE) !void {
        const host_is_64 = @sizeOf(usize) == 8;
        if (self.is_32bit and host_is_64) return error.CannotLoad32BitPEIn64BitProcess;
        if (!self.is_32bit and !host_is_64) return error.CannotLoad64BitPEIn32BitProcess;
    }

    /// Allocate memory for the PE image
    pub fn allocateMemory(self: *RunPE) !void {
        self.addr_alloc = win.VirtualAlloc(
            null,
            self.get_image_size(),
            win.MEM_COMMIT | win.MEM_RESERVE,
            win.PAGE_READWRITE,
        );
        self.addr_array_ptr = @ptrCast(self.addr_alloc orelse return error.AllocationFailed);
    }

    /// Copy the PE headers to the allocated memory
    pub fn copyHeaders(self: *RunPE) !void {
        const header_size = self.get_headers_size();
        @memcpy(self.addr_array_ptr[0..header_size], self.buffer[0..header_size]);
        try self.get_dos_header();
    }

    /// Compute the address of the first section header.
    /// Section headers start at: e_lfanew + 4 (Signature) + 20 (FileHeader) + SizeOfOptionalHeader
    fn sectionHeaderBase(self: *RunPE) usize {
        return @intFromPtr(self.addr_array_ptr) +
            @as(usize, @intCast(self.dosheader.e_lfanew)) +
            4 + @sizeOf(win.IMAGE_FILE_HEADER) +
            @as(usize, self.ntheaders.sizeOfOptionalHeader());
    }

    /// Write each section of the PE file to the allocated memory
    fn write_sections(self: *RunPE) !void {
        const section_base = self.sectionHeaderBase();
        for (0..self.ntheaders.numberOfSections()) |count| {
            const nt_section_header: *win.IMAGE_SECTION_HEADER = @ptrFromInt(section_base + (count * @sizeOf(win.IMAGE_SECTION_HEADER)));
            if (nt_section_header.PointerToRawData == 0 or nt_section_header.SizeOfRawData == 0) continue;
            if (nt_section_header.PointerToRawData + nt_section_header.SizeOfRawData > self.buffer.len) return error.SectionOutOfBounds;
            const src = self.buffer[nt_section_header.PointerToRawData..][0..nt_section_header.SizeOfRawData];
            @memcpy((self.addr_array_ptr + nt_section_header.VirtualAddress)[0..src.len], src);
        }
    }

    /// Write the import table of the PE file to the allocated memory.
    /// PE32 uses 4-byte thunks (IMAGE_THUNK_DATA32), PE32+ uses 8-byte thunks.
    fn write_import_table(self: *RunPE) !void {
        const data_dir = self.ntheaders.dataDirectory();
        if (data_dir[IMAGE_DIRECTORY_ENTRY_IMPORT].Size == 0) return;

        var importDescriptorPtr: *win.IMAGE_IMPORT_DESCRIPTOR = @ptrFromInt(
            @intFromPtr(self.addr_array_ptr) + @as(usize, data_dir[IMAGE_DIRECTORY_ENTRY_IMPORT].VirtualAddress),
        );

        while (importDescriptorPtr.Name != 0 and importDescriptorPtr.FirstThunk != 0) : (importDescriptorPtr = @ptrFromInt(@intFromPtr(importDescriptorPtr) + @sizeOf(win.IMAGE_IMPORT_DESCRIPTOR))) {
            const dll_name_ptr: [*:0]const u8 = @ptrFromInt(@intFromPtr(self.addr_array_ptr) + @as(usize, @intCast(importDescriptorPtr.Name)));
            const dll_handle: win.HMODULE = win.LoadLibraryA(std.mem.sliceTo(dll_name_ptr, 0).ptr) orelse return error.ImportResolutionFailed;

            if (self.is_32bit) {
                try self.resolveImports32(importDescriptorPtr, dll_handle);
            } else {
                try self.resolveImports64(importDescriptorPtr, dll_handle);
            }
        }
    }

    /// Resolve imports for PE32 (4-byte thunks)
    fn resolveImports32(self: *RunPE, desc: *win.IMAGE_IMPORT_DESCRIPTOR, dll_handle: win.HMODULE) !void {
        const ordinal_flag: u32 = 1 << 31;
        var thunk: *align(1) u32 = @ptrFromInt(@intFromPtr(self.addr_array_ptr) + desc.FirstThunk);
        while (thunk.* != 0) : (thunk = @ptrFromInt(@intFromPtr(thunk) + @sizeOf(u32))) {
            const proc_addr = if (thunk.* & ordinal_flag != 0)
                win.GetProcAddress(
                    @ptrCast(dll_handle),
                    @ptrFromInt(@as(usize, @as(u16, @truncate(thunk.* & 0xFFFF)))),
                )
            else
                win.GetProcAddress(
                    @ptrCast(dll_handle),
                    @ptrCast(&@as(*align(1) const win.IMAGE_IMPORT_BY_NAME, @ptrFromInt(@intFromPtr(self.addr_array_ptr) + thunk.*)).Name[0]),
                );

            thunk.* = @truncate(@intFromPtr(proc_addr orelse return error.ImportResolutionFailed));
        }
    }

    /// Resolve imports for PE32+ (8-byte thunks)
    fn resolveImports64(self: *RunPE, desc: *win.IMAGE_IMPORT_DESCRIPTOR, dll_handle: win.HMODULE) !void {
        const ordinal_flag: u64 = 1 << 63;
        var thunk: *align(1) u64 = @ptrFromInt(@intFromPtr(self.addr_array_ptr) + desc.FirstThunk);
        while (thunk.* != 0) : (thunk = @ptrFromInt(@intFromPtr(thunk) + @sizeOf(u64))) {
            const proc_addr = if (thunk.* & ordinal_flag != 0)
                win.GetProcAddress(
                    @ptrCast(dll_handle),
                    @ptrFromInt(@as(usize, @as(u16, @truncate(thunk.* & 0xFFFF)))),
                )
            else
                win.GetProcAddress(
                    @ptrCast(dll_handle),
                    @ptrCast(&@as(*align(1) const win.IMAGE_IMPORT_BY_NAME, @ptrFromInt(@intFromPtr(self.addr_array_ptr) + @as(usize, @truncate(thunk.*)))).Name[0]),
                );

            thunk.* = @intFromPtr(proc_addr orelse return error.ImportResolutionFailed);
        }
    }

    /// Fix PE base relocations
    fn fix_base_relocations(self: *RunPE) !void {
        const data_dir = self.ntheaders.dataDirectory();
        if (data_dir[IMAGE_DIRECTORY_ENTRY_BASERELOC].Size == 0) return;

        const base_addr = @intFromPtr(self.addr_array_ptr);
        const image_base = self.ntheaders.imageBase();

        var reloc_block: *win.IMAGE_BASE_RELOCATION = @ptrCast(@alignCast(
            self.addr_array_ptr + data_dir[IMAGE_DIRECTORY_ENTRY_BASERELOC].VirtualAddress,
        ));

        while (reloc_block.SizeOfBlock != 0) : (reloc_block = @ptrFromInt(@intFromPtr(reloc_block) + reloc_block.SizeOfBlock)) {
            const entry_count = (reloc_block.SizeOfBlock - @sizeOf(win.IMAGE_BASE_RELOCATION)) / 2;
            const entries: [*]u16 = @ptrCast(@alignCast(@as([*]u8, @ptrCast(reloc_block)) + @sizeOf(win.IMAGE_BASE_RELOCATION)));

            for (entries[0..entry_count]) |entry| {
                const offset = entry & 0xFFF;
                const reloc_type: u4 = @truncate(entry >> 12);
                const target_addr = self.addr_array_ptr + reloc_block.VirtualAddress + offset;

                switch (reloc_type) {
                    IMAGE_REL_BASED_HIGHLOW => {
                        // 32-bit relocation: read/write u32
                        const ptr: *align(1) u32 = @ptrCast(target_addr);
                        const delta: i64 = @as(i64, @intCast(base_addr)) - @as(i64, @intCast(image_base));
                        ptr.* = @bitCast(@as(i32, @truncate(@as(i64, @as(i32, @bitCast(ptr.*))) + delta)));
                    },
                    IMAGE_REL_BASED_DIR64 => {
                        // 64-bit relocation: read/write u64
                        const ptr: *align(1) u64 = @ptrCast(target_addr);
                        const delta: i64 = @as(i64, @intCast(base_addr)) - @as(i64, @intCast(image_base));
                        ptr.* = @bitCast(@as(i64, @bitCast(ptr.*)) + delta);
                    },
                    IMAGE_REL_BASED_ARM_MOV32 => {
                        const delta_u32: u32 = @truncate(@as(u64, @bitCast(
                            @as(i64, @intCast(base_addr)) - @as(i64, @intCast(image_base)),
                        )));
                        const current = armMov32Extract(target_addr);
                        armMov32Encode(target_addr, current +% delta_u32);
                    },
                    IMAGE_REL_BASED_THUMB_MOV32 => {
                        const delta_u32: u32 = @truncate(@as(u64, @bitCast(
                            @as(i64, @intCast(base_addr)) - @as(i64, @intCast(image_base)),
                        )));
                        const current = thumbMov32Extract(target_addr);
                        thumbMov32Encode(target_addr, current +% delta_u32);
                    },
                    IMAGE_REL_BASED_ABSOLUTE => {},
                    else => return error.UnsupportedRelocationType,
                }
            }
        }
    }

    /// Change memory protection for PE sections
    fn changeMemoryProtection(self: *RunPE) !void {
        var old_protect: win.DWORD = undefined;
        const section_base = self.sectionHeaderBase();

        for (0..self.ntheaders.numberOfSections()) |i| {
            const section: *win.IMAGE_SECTION_HEADER = @ptrFromInt(section_base + (i * @sizeOf(win.IMAGE_SECTION_HEADER)));
            const chars = section.Characteristics;
            const is_exec = chars & win.IMAGE_SCN_MEM_EXECUTE != 0;
            const is_write = chars & win.IMAGE_SCN_MEM_WRITE != 0;

            const new_protect: win.DWORD = if (is_exec and is_write)
                win.PAGE_EXECUTE_READWRITE
            else if (is_exec)
                win.PAGE_EXECUTE_READ
            else if (is_write)
                win.PAGE_READWRITE
            else
                win.PAGE_READONLY;

            if (win.VirtualProtect(
                self.addr_array_ptr + section.VirtualAddress,
                section.Misc.VirtualSize,
                new_protect,
                &old_protect,
            ) == 0) return error.VirtualProtectFailed;
        }
    }

    // ----------------------------------------------------------------
    // Delayed imports
    // ----------------------------------------------------------------

    /// Resolve delayed imports from DataDirectory[13].
    fn writeDelayedImportTable(self: *RunPE) !void {
        const data_dir = self.ntheaders.dataDirectory();
        if (data_dir[IMAGE_DIRECTORY_ENTRY_DELAY_IMPORT].Size == 0) return;

        var desc: *const IMAGE_DELAYLOAD_DESCRIPTOR = @ptrCast(@alignCast(
            self.addr_array_ptr + data_dir[IMAGE_DIRECTORY_ENTRY_DELAY_IMPORT].VirtualAddress,
        ));

        while (desc.DllNameRVA != 0) : (desc = @ptrFromInt(@intFromPtr(desc) + @sizeOf(IMAGE_DELAYLOAD_DESCRIPTOR))) {
            // Only handle modern format (RVAs)
            if (desc.Attributes & 1 == 0) continue;

            const dll_name_ptr: [*:0]const u8 = @ptrFromInt(
                @intFromPtr(self.addr_array_ptr) + @as(usize, desc.DllNameRVA),
            );
            const dll_handle: win.HMODULE = win.LoadLibraryA(
                std.mem.sliceTo(dll_name_ptr, 0).ptr,
            ) orelse continue;

            if (self.is_32bit) {
                try self.resolveDelayedImports32(desc, dll_handle);
            } else {
                try self.resolveDelayedImports64(desc, dll_handle);
            }

            // Store module handle
            if (desc.ModuleHandleRVA != 0) {
                if (self.is_32bit) {
                    const h_ptr: *align(1) u32 = @ptrFromInt(
                        @intFromPtr(self.addr_array_ptr) + @as(usize, desc.ModuleHandleRVA),
                    );
                    h_ptr.* = @truncate(@intFromPtr(dll_handle));
                } else {
                    const h_ptr: *align(1) u64 = @ptrFromInt(
                        @intFromPtr(self.addr_array_ptr) + @as(usize, desc.ModuleHandleRVA),
                    );
                    h_ptr.* = @intFromPtr(dll_handle);
                }
            }
        }
    }

    fn resolveDelayedImports32(
        self: *RunPE,
        desc: *const IMAGE_DELAYLOAD_DESCRIPTOR,
        dll_handle: win.HMODULE,
    ) !void {
        const ordinal_flag: u32 = 1 << 31;
        var int_ptr: *align(1) u32 = @ptrFromInt(
            @intFromPtr(self.addr_array_ptr) + @as(usize, desc.ImportNameTableRVA),
        );
        var iat_ptr: *align(1) u32 = @ptrFromInt(
            @intFromPtr(self.addr_array_ptr) + @as(usize, desc.ImportAddressTableRVA),
        );

        while (int_ptr.* != 0) {
            const proc_addr = if (int_ptr.* & ordinal_flag != 0)
                win.GetProcAddress(
                    @ptrCast(dll_handle),
                    @ptrFromInt(@as(usize, @as(u16, @truncate(int_ptr.* & 0xFFFF)))),
                )
            else
                win.GetProcAddress(
                    @ptrCast(dll_handle),
                    @ptrCast(&@as(*align(1) const win.IMAGE_IMPORT_BY_NAME, @ptrFromInt(@intFromPtr(self.addr_array_ptr) + int_ptr.*)).Name[0]),
                );

            iat_ptr.* = @truncate(@intFromPtr(proc_addr orelse return error.DelayedImportResolutionFailed));
            int_ptr = @ptrFromInt(@intFromPtr(int_ptr) + 4);
            iat_ptr = @ptrFromInt(@intFromPtr(iat_ptr) + 4);
        }
    }

    fn resolveDelayedImports64(
        self: *RunPE,
        desc: *const IMAGE_DELAYLOAD_DESCRIPTOR,
        dll_handle: win.HMODULE,
    ) !void {
        const ordinal_flag: u64 = 1 << 63;
        var int_ptr: *align(1) u64 = @ptrFromInt(
            @intFromPtr(self.addr_array_ptr) + @as(usize, desc.ImportNameTableRVA),
        );
        var iat_ptr: *align(1) u64 = @ptrFromInt(
            @intFromPtr(self.addr_array_ptr) + @as(usize, desc.ImportAddressTableRVA),
        );

        while (int_ptr.* != 0) {
            const proc_addr = if (int_ptr.* & ordinal_flag != 0)
                win.GetProcAddress(
                    @ptrCast(dll_handle),
                    @ptrFromInt(@as(usize, @as(u16, @truncate(int_ptr.* & 0xFFFF)))),
                )
            else
                win.GetProcAddress(
                    @ptrCast(dll_handle),
                    @ptrCast(&@as(*align(1) const win.IMAGE_IMPORT_BY_NAME, @ptrFromInt(@intFromPtr(self.addr_array_ptr) + @as(usize, @truncate(int_ptr.*)))).Name[0]),
                );

            iat_ptr.* = @intFromPtr(proc_addr orelse return error.DelayedImportResolutionFailed);
            int_ptr = @ptrFromInt(@intFromPtr(int_ptr) + 8);
            iat_ptr = @ptrFromInt(@intFromPtr(iat_ptr) + 8);
        }
    }

    // ----------------------------------------------------------------
    // Exception table registration (PDATA)
    // ----------------------------------------------------------------

    /// Register exception table for structured exception handling (x64/ARM64 only).
    fn registerExceptionTable(self: *RunPE) void {
        if (self.is_32bit) return;

        const data_dir = self.ntheaders.dataDirectory();
        if (data_dir[IMAGE_DIRECTORY_ENTRY_EXCEPTION].Size == 0) return;

        const table_ptr: *const RUNTIME_FUNCTION = @ptrCast(@alignCast(
            self.addr_array_ptr + data_dir[IMAGE_DIRECTORY_ENTRY_EXCEPTION].VirtualAddress,
        ));
        const entry_count = data_dir[IMAGE_DIRECTORY_ENTRY_EXCEPTION].Size / 12;

        const result = win.RtlAddFunctionTable(
            @ptrCast(@constCast(table_ptr)),
            entry_count,
            @intFromPtr(self.addr_array_ptr),
        );
        if (result != 0) {
            self.exception_table_ptr = table_ptr;
        }
    }

    /// Unregister exception tables before freeing memory.
    fn unregisterExceptionTable(self: *RunPE) void {
        if (self.exception_table_ptr) |ptr| {
            _ = win.RtlDeleteFunctionTable(@ptrCast(@constCast(ptr)));
            self.exception_table_ptr = null;
        }
    }

    // ----------------------------------------------------------------
    // TLS (Thread Local Storage) callbacks
    // ----------------------------------------------------------------

    /// Process TLS callbacks. Called AFTER memory protections, BEFORE entry point.
    fn processTlsCallbacks(self: *RunPE) void {
        const data_dir = self.ntheaders.dataDirectory();
        if (data_dir[IMAGE_DIRECTORY_ENTRY_TLS].Size == 0) return;

        const tls_addr = @intFromPtr(self.addr_array_ptr) +
            @as(usize, data_dir[IMAGE_DIRECTORY_ENTRY_TLS].VirtualAddress);
        const base = @intFromPtr(self.addr_array_ptr);

        const TlsCallback = *const fn (?*anyopaque, u32, ?*anyopaque) callconv(.c) void;

        if (self.is_32bit) {
            const tls: *const extern struct {
                StartAddressOfRawData: u32,
                EndAddressOfRawData: u32,
                AddressOfIndex: u32,
                AddressOfCallBacks: u32,
                SizeOfZeroFill: u32,
                Characteristics: u32,
            } = @ptrFromInt(tls_addr);

            if (tls.AddressOfIndex != 0) {
                const idx_ptr: *align(1) u32 = @ptrFromInt(@as(usize, tls.AddressOfIndex));
                idx_ptr.* = 0;
            }

            if (tls.AddressOfCallBacks != 0) {
                var cb_ptr: [*]align(1) const u32 = @ptrFromInt(@as(usize, tls.AddressOfCallBacks));
                while (cb_ptr[0] != 0) {
                    const callback: TlsCallback = @ptrFromInt(@as(usize, cb_ptr[0]));
                    callback(@ptrFromInt(base), DLL_PROCESS_ATTACH, null);
                    cb_ptr = @ptrFromInt(@intFromPtr(cb_ptr) + 4);
                }
            }
        } else {
            const tls: *const extern struct {
                StartAddressOfRawData: u64,
                EndAddressOfRawData: u64,
                AddressOfIndex: u64,
                AddressOfCallBacks: u64,
                SizeOfZeroFill: u32,
                Characteristics: u32,
            } = @ptrFromInt(tls_addr);

            if (tls.AddressOfIndex != 0) {
                const idx_ptr: *align(1) u32 = @ptrFromInt(@as(usize, @truncate(tls.AddressOfIndex)));
                idx_ptr.* = 0;
            }

            if (tls.AddressOfCallBacks != 0) {
                var cb_ptr: [*]align(1) const u64 = @ptrFromInt(@as(usize, @truncate(tls.AddressOfCallBacks)));
                while (cb_ptr[0] != 0) {
                    const callback: TlsCallback = @ptrFromInt(@as(usize, @truncate(cb_ptr[0])));
                    callback(@ptrFromInt(base), DLL_PROCESS_ATTACH, null);
                    cb_ptr = @ptrFromInt(@intFromPtr(cb_ptr) + 8);
                }
            }
        }
    }

    /// Create and run a new thread for the loaded PE
    fn createAndRunThread(self: *RunPE) !win.HANDLE {
        const entry_rva = self.ntheaders.addressOfEntryPoint();
        const thread_handle = win.CreateThread(
            null,
            0,
            @as(win.LPTHREAD_START_ROUTINE, @ptrCast(@alignCast(
                @as(*const fn () callconv(.c) void, @ptrFromInt(@intFromPtr(self.addr_array_ptr) + entry_rva)),
            ))),
            null,
            0,
            null,
        );
        return thread_handle orelse return error.ThreadCreationFailed;
    }

    /// Execute the loaded PE file
    fn executeLoadedPE(self: *RunPE) !void {
        const thread_handle = try self.createAndRunThread();
        defer _ = win.CloseHandle(thread_handle);
        _ = try utils.waitForThreadCompletion(thread_handle);
    }

    /// Main function to run the PE file
    pub fn run(self: *RunPE) !void {
        return self.runWithArgs(&.{});
    }

    /// Run the PE file with arguments (passed to Main(string[]) for .NET assemblies)
    pub fn runWithArgs(self: *RunPE, args: []const []const u8) !void {
        try self.allocateMemory();
        defer {
            self.unregisterExceptionTable();
            _ = win.VirtualFree(self.addr_alloc, 0, win.MEM_RELEASE);
        }
        try self.copyHeaders();
        try self.get_nt_header();

        if (utils.is_dotnet_assembly(self.ntheaders)) {
            try dotnet.executeDotNetAssembly(self.buffer, args);
        } else {
            try self.validateArchitecture();
            try self.write_sections();
            try self.write_import_table();
            try self.fix_base_relocations();
            try self.writeDelayedImportTable();
            self.registerExceptionTable();
            try self.changeMemoryProtection();
            self.processTlsCallbacks();
            try self.executeLoadedPE();
        }
    }
};

// ============================================================================
// Export table resolution (standalone utilities)
// ============================================================================

/// Resolve an export by name from a loaded PE image.
/// Returns a function pointer, or null if not found or forwarded.
pub fn getExportByName(
    base: [*]const u8,
    ntheaders: NtHeaders,
    name: [*:0]const u8,
) ?*anyopaque {
    const data_dir = ntheaders.dataDirectory();
    if (data_dir[IMAGE_DIRECTORY_ENTRY_EXPORT].Size == 0) return null;

    const export_dir_start = @as(usize, data_dir[IMAGE_DIRECTORY_ENTRY_EXPORT].VirtualAddress);
    const export_dir_end = export_dir_start + @as(usize, data_dir[IMAGE_DIRECTORY_ENTRY_EXPORT].Size);

    const exports: *const IMAGE_EXPORT_DIRECTORY = @ptrCast(@alignCast(base + export_dir_start));

    const names: [*]align(1) const u32 = @ptrCast(base + exports.AddressOfNames);
    const ordinals: [*]align(1) const u16 = @ptrCast(base + exports.AddressOfNameOrdinals);
    const functions: [*]align(1) const u32 = @ptrCast(base + exports.AddressOfFunctions);

    const target_name = std.mem.sliceTo(name, 0);

    for (0..exports.NumberOfNames) |i| {
        const name_rva = names[i];
        const export_name: [*:0]const u8 = @ptrCast(base + name_rva);
        const export_name_slice = std.mem.sliceTo(export_name, 0);

        if (std.mem.eql(u8, export_name_slice, target_name)) {
            const ordinal_index = @as(usize, ordinals[i]);
            const func_rva = @as(usize, functions[ordinal_index]);

            if (func_rva >= export_dir_start and func_rva < export_dir_end) return null;
            return @ptrFromInt(@intFromPtr(base) + func_rva);
        }
    }
    return null;
}

/// Resolve an export by ordinal from a loaded PE image.
pub fn getExportByOrdinal(
    base: [*]const u8,
    ntheaders: NtHeaders,
    ordinal: u16,
) ?*anyopaque {
    const data_dir = ntheaders.dataDirectory();
    if (data_dir[IMAGE_DIRECTORY_ENTRY_EXPORT].Size == 0) return null;

    const export_dir_start = @as(usize, data_dir[IMAGE_DIRECTORY_ENTRY_EXPORT].VirtualAddress);
    const export_dir_end = export_dir_start + @as(usize, data_dir[IMAGE_DIRECTORY_ENTRY_EXPORT].Size);

    const exports: *const IMAGE_EXPORT_DIRECTORY = @ptrCast(@alignCast(base + export_dir_start));

    const index = @as(u32, ordinal) -% exports.Base;
    if (index >= exports.NumberOfFunctions) return null;

    const functions: [*]align(1) const u32 = @ptrCast(base + exports.AddressOfFunctions);
    const func_rva = @as(usize, functions[@as(usize, index)]);
    if (func_rva == 0) return null;

    if (func_rva >= export_dir_start and func_rva < export_dir_end) return null;
    return @ptrFromInt(@intFromPtr(base) + func_rva);
}
