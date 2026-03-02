const std = @import("std");
const builtin = @import("builtin");
const utils = @import("utils.zig");
const build_options = @import("build_options");
const dotnet = if (build_options.dotnet) @import("dotnet.zig") else undefined;
const win = @cImport(@cInclude("win32.h"));

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
pub const IMAGE_DIRECTORY_ENTRY_EXPORT: usize = 0;
pub const IMAGE_DIRECTORY_ENTRY_IMPORT: usize = 1;
pub const IMAGE_DIRECTORY_ENTRY_RESOURCE: usize = 2;
const IMAGE_DIRECTORY_ENTRY_EXCEPTION: usize = 3;
pub const IMAGE_DIRECTORY_ENTRY_BASERELOC: usize = 5;
pub const IMAGE_DIRECTORY_ENTRY_TLS: usize = 9;
pub const IMAGE_DIRECTORY_ENTRY_LOAD_CONFIG: usize = 10;
pub const IMAGE_DIRECTORY_ENTRY_BOUND_IMPORT: usize = 11;
pub const IMAGE_DIRECTORY_ENTRY_DELAY_IMPORT: usize = 13;
pub const IMAGE_DIRECTORY_ENTRY_COM_DESCRIPTOR: usize = 14;

// CFG constants
pub const IMAGE_GUARD_CF_INSTRUMENTED: u32 = 0x0000_0100;
pub const IMAGE_GUARD_CF_FUNCTION_TABLE_PRESENT: u32 = 0x0000_0400;
pub const CFG_CALL_TARGET_VALID: usize = 0x0000_0001;

const CFG_CALL_TARGET_INFO = extern struct {
    Offset: usize,
    Flags: usize,
};

// API Set Schema structs
const API_SET_NAMESPACE = extern struct {
    Version: u32,
    Size: u32,
    Flags: u32,
    Count: u32,
    EntryOffset: u32,
    HashOffset: u32,
    HashFactor: u32,
};

const API_SET_NAMESPACE_ENTRY = extern struct {
    Flags: u32,
    NameOffset: u32,
    NameLength: u32,
    HashedLength: u32,
    ValueOffset: u32,
    ValueCount: u32,
};

const API_SET_VALUE_ENTRY = extern struct {
    Flags: u32,
    NameOffset: u32,
    NameLength: u32,
    ValueOffset: u32,
    ValueLength: u32,
};

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
// Debug logging (compiles to nothing in non-Debug builds)
// ============================================================================

fn debugLog(comptime fmt: []const u8, args: anytype) void {
    if (builtin.mode == .Debug) {
        var buf: [512]u8 = undefined;
        const slice = std.fmt.bufPrint(&buf, fmt, args) catch return;
        buf[slice.len] = 0;
        win.OutputDebugStringA(@ptrCast(slice.ptr));
    }
}

// ============================================================================
// ARM relocation helpers
// ============================================================================

/// Extract 32-bit value from ARM MOVW+MOVT instruction pair.
pub fn armMov32Extract(addr: [*]const u8) u32 {
    const movw = std.mem.readInt(u32, addr[0..4], .little);
    const movt = std.mem.readInt(u32, addr[4..8], .little);
    const low: u32 = ((movw >> 4) & 0xF000) | (movw & 0xFFF);
    const high: u32 = ((movt >> 4) & 0xF000) | (movt & 0xFFF);
    return (high << 16) | low;
}

/// Encode 32-bit value back into ARM MOVW+MOVT instruction pair.
pub fn armMov32Encode(addr: [*]u8, value: u32) void {
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
pub fn thumbMov32Extract(addr: [*]const u8) u32 {
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
pub fn thumbMov32Encode(addr: [*]u8, value: u32) void {
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
            const dll_name_slice = std.mem.sliceTo(dll_name_ptr, 0);

            // Try API set resolution for api-ms-win-* and ext-ms-win-* DLLs
            var api_set_buf: [256]u8 = undefined;
            const dll_handle: win.HMODULE = blk: {
                if (resolveApiSet(dll_name_slice, &api_set_buf)) |_| {
                    break :blk win.LoadLibraryA(@ptrCast(&api_set_buf)) orelse
                        (win.LoadLibraryA(dll_name_slice.ptr) orelse return error.ImportResolutionFailed);
                }
                break :blk win.LoadLibraryA(dll_name_slice.ptr) orelse return error.ImportResolutionFailed;
            };

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
            const dll_name_slice = std.mem.sliceTo(dll_name_ptr, 0);

            // Try API set resolution
            var api_set_buf: [256]u8 = undefined;
            const dll_handle: win.HMODULE = blk: {
                if (resolveApiSet(dll_name_slice, &api_set_buf)) |_| {
                    break :blk win.LoadLibraryA(@ptrCast(&api_set_buf)) orelse
                        (win.LoadLibraryA(dll_name_slice.ptr) orelse continue);
                }
                break :blk win.LoadLibraryA(dll_name_slice.ptr) orelse continue;
            };

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
    fn registerExceptionTable(self: *RunPE) !void {
        if (comptime builtin.cpu.arch == .x86) return;
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
        if (comptime builtin.cpu.arch == .x86) return;
        if (self.exception_table_ptr) |ptr| {
            _ = win.RtlDeleteFunctionTable(@ptrCast(@constCast(ptr)));
            self.exception_table_ptr = null;
        }
    }

    // ----------------------------------------------------------------
    // TLS (Thread Local Storage) callbacks
    // ----------------------------------------------------------------

    /// Process TLS callbacks. Called AFTER memory protections, BEFORE entry point.
    fn processTlsCallbacks(self: *RunPE) !void {
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

    // ----------------------------------------------------------------
    // Bound imports invalidation
    // ----------------------------------------------------------------

    /// Zero the Bound Import data directory to prevent stale pre-resolved addresses.
    fn zeroBoundImportDirectory(self: *RunPE) void {
        var data_dir = self.ntheaders.dataDirectory();
        data_dir[IMAGE_DIRECTORY_ENTRY_BOUND_IMPORT].VirtualAddress = 0;
        data_dir[IMAGE_DIRECTORY_ENTRY_BOUND_IMPORT].Size = 0;
    }

    // ----------------------------------------------------------------
    // Security cookie initialization
    // ----------------------------------------------------------------

    /// Initialize __security_cookie from Load Config directory.
    fn initializeSecurityCookie(self: *RunPE) void {
        const data_dir = self.ntheaders.dataDirectory();
        if (data_dir[IMAGE_DIRECTORY_ENTRY_LOAD_CONFIG].Size == 0 or
            data_dir[IMAGE_DIRECTORY_ENTRY_LOAD_CONFIG].VirtualAddress == 0) return;

        const lc_addr = @intFromPtr(self.addr_array_ptr) +
            @as(usize, data_dir[IMAGE_DIRECTORY_ENTRY_LOAD_CONFIG].VirtualAddress);

        const lc_size: usize = @as(*align(1) const u32, @ptrFromInt(lc_addr)).*;

        // SecurityCookie VA offset: PE32 = 60 (needs >= 64), PE32+ = 96 (needs >= 104)
        const cookie_va: usize = if (self.is_32bit) blk: {
            if (lc_size < 64) return;
            break :blk @as(usize, @as(*align(1) const u32, @ptrFromInt(lc_addr + 60)).*);
        } else blk: {
            if (lc_size < 104) return;
            break :blk @as(usize, @truncate(@as(*align(1) const u64, @ptrFromInt(lc_addr + 96)).*));
        };

        if (cookie_va == 0) return;

        // Generate random value using rdtsc / cntvct_el0
        const random_value: usize = blk: {
            if (builtin.cpu.arch == .x86_64 or builtin.cpu.arch == .x86) {
                var lo: u32 = undefined;
                var hi: u32 = undefined;
                asm volatile ("rdtsc"
                    : [lo] "={eax}" (lo),
                      [hi] "={edx}" (hi),
                );
                break :blk if (@sizeOf(usize) == 8)
                    (@as(usize, hi) << 32) | @as(usize, lo)
                else
                    lo ^ (hi << 16);
            } else if (builtin.cpu.arch == .aarch64) {
                var cnt: u64 = undefined;
                asm volatile ("mrs %[cnt], cntvct_el0"
                    : [cnt] "=r" (cnt),
                );
                break :blk @as(usize, @truncate(cnt));
            } else {
                break :blk 0x12345678; // fallback
            }
        };

        const cookie_value = if (random_value == 0 or random_value == 0x00002B992DDFA232)
            random_value ^ 0xDEADBEEF
        else
            random_value;

        if (self.is_32bit) {
            @as(*align(1) u32, @ptrFromInt(cookie_va)).* = @truncate(cookie_value);
        } else {
            @as(*align(1) u64, @ptrFromInt(cookie_va)).* = @as(u64, cookie_value);
        }

        debugLog("[runpe] Security cookie initialized at VA 0x{X}\n", .{cookie_va});
    }

    // ----------------------------------------------------------------
    // CFG (Control Flow Guard)
    // ----------------------------------------------------------------

    /// Register valid CFG call targets for the loaded PE.
    fn setupCfg(self: *RunPE) void {
        const data_dir = self.ntheaders.dataDirectory();
        if (data_dir[IMAGE_DIRECTORY_ENTRY_LOAD_CONFIG].Size == 0 or
            data_dir[IMAGE_DIRECTORY_ENTRY_LOAD_CONFIG].VirtualAddress == 0) return;

        const lc_addr = @intFromPtr(self.addr_array_ptr) +
            @as(usize, data_dir[IMAGE_DIRECTORY_ENTRY_LOAD_CONFIG].VirtualAddress);
        const lc_size: usize = @as(*align(1) const u32, @ptrFromInt(lc_addr)).*;

        // GuardFlags, GuardCFFunctionTable, GuardCFFunctionCount offsets
        const guard_flags_off: usize = if (self.is_32bit) 88 else 144;
        const table_off: usize = if (self.is_32bit) 76 else 128;
        const count_off: usize = if (self.is_32bit) 80 else 136;
        const min_size: usize = if (self.is_32bit) 92 else 148;

        if (lc_size < min_size) return;

        const guard_flags = @as(*align(1) const u32, @ptrFromInt(lc_addr + guard_flags_off)).*;
        if (guard_flags & IMAGE_GUARD_CF_INSTRUMENTED == 0) return;
        if (guard_flags & IMAGE_GUARD_CF_FUNCTION_TABLE_PRESENT == 0) return;

        const func_table_va: usize = if (self.is_32bit)
            @as(usize, @as(*align(1) const u32, @ptrFromInt(lc_addr + table_off)).*)
        else
            @as(usize, @truncate(@as(*align(1) const u64, @ptrFromInt(lc_addr + table_off)).*));

        const func_count: usize = if (self.is_32bit)
            @as(usize, @as(*align(1) const u32, @ptrFromInt(lc_addr + count_off)).*)
        else
            @as(usize, @truncate(@as(*align(1) const u64, @ptrFromInt(lc_addr + count_off)).*));

        if (func_table_va == 0 or func_count == 0) return;

        const extra_bytes: usize = @as(usize, (guard_flags >> 28) & 0xF);
        const stride = 4 + extra_bytes;

        // Load SetProcessValidCallTargets from kernelbase.dll
        const kernelbase = win.LoadLibraryA("kernelbase.dll") orelse return;
        const set_valid_ptr = win.GetProcAddress(@ptrCast(kernelbase), "SetProcessValidCallTargets") orelse return;
        const FnSetValid = *const fn (
            win.HANDLE,
            ?*anyopaque,
            usize,
            u32,
            [*]CFG_CALL_TARGET_INFO,
        ) callconv(.c) i32;
        const set_valid: FnSetValid = @ptrCast(set_valid_ptr);

        // Build target array on stack (up to 4096 entries) or heap
        if (func_count > 65536) return; // sanity check
        var targets_buf: [65536]CFG_CALL_TARGET_INFO = undefined;
        for (0..func_count) |i| {
            const entry_addr = func_table_va + i * stride;
            const rva: usize = @as(*align(1) const u32, @ptrFromInt(entry_addr)).*;
            targets_buf[i] = .{ .Offset = rva, .Flags = CFG_CALL_TARGET_VALID };
        }

        const img_size: usize = switch (self.ntheaders) {
            .pe32 => |h| @as(usize, h.OptionalHeader.SizeOfImage),
            .pe64 => |h| @as(usize, h.OptionalHeader.SizeOfImage),
        };

        _ = set_valid(
            win.GetCurrentProcess(),
            @ptrCast(self.addr_array_ptr),
            img_size,
            @intCast(func_count),
            &targets_buf,
        );

        debugLog("[runpe] CFG: registered {} valid call targets\n", .{func_count});
    }

    // ----------------------------------------------------------------
    // SxS / Activation Context
    // ----------------------------------------------------------------

    const SxsGuard = struct {
        handle: win.HANDLE,
        cookie: usize,
    };

    /// Activate an SxS context from the PE's embedded manifest.
    fn activateSxsContext(self: *RunPE) ?SxsGuard {
        const data_dir = self.ntheaders.dataDirectory();
        if (data_dir[IMAGE_DIRECTORY_ENTRY_RESOURCE].Size == 0) return null;

        const ACTCTX_FLAG_RESOURCE_NAME_VALID: u32 = 0x0000_0008;
        const ACTCTX_FLAG_HMODULE_VALID: u32 = 0x0000_0080;

        // Use raw bytes approach to build ACTCTXW since the C-import struct has
        // alignment constraints that prevent MAKEINTRESOURCE(1) usage directly.
        // Dynamically load CreateActCtxW from kernel32.
        const kernel32 = win.LoadLibraryA("kernel32.dll") orelse return null;
        const FnCreateActCtxW = *const fn (*anyopaque) callconv(.c) ?*anyopaque;
        const FnActivateActCtx = *const fn (?*anyopaque, *usize) callconv(.c) i32;

        const create_act_ctx: FnCreateActCtxW = @ptrCast(
            win.GetProcAddress(@ptrCast(kernel32), "CreateActCtxW") orelse return null,
        );
        const activate_act_ctx: FnActivateActCtx = @ptrCast(
            win.GetProcAddress(@ptrCast(kernel32), "ActivateActCtx") orelse return null,
        );

        // Build ACTCTXW manually in memory
        // Layout: cbSize(4) + dwFlags(4) + lpSource(ptr) + wProcessorArchitecture(2) + wLangId(2) + pad(4 on x64) +
        //         lpAssemblyDirectory(ptr) + lpResourceName(ptr) + lpApplicationName(ptr) + hModule(ptr)
        var empty_source = [_:0]u16{0};
        var actctx_bytes: [128]u8 = std.mem.zeroes([128]u8);
        const ptr_size = @sizeOf(usize);
        // cbSize at offset 0 (u32)
        @as(*align(1) u32, @ptrCast(&actctx_bytes[0])).* = @sizeOf(win.ACTCTXW);
        // dwFlags at offset 4 (u32)
        @as(*align(1) u32, @ptrCast(&actctx_bytes[4])).* = ACTCTX_FLAG_RESOURCE_NAME_VALID | ACTCTX_FLAG_HMODULE_VALID;
        // lpSource at offset 8 (pointer)
        @as(*align(1) usize, @ptrCast(&actctx_bytes[8])).* = @intFromPtr(&empty_source);
        // wProcessorArchitecture at offset 8+ptr_size (u16) = 0
        // wLangId at offset 8+ptr_size+2 (u16) = 0
        // lpAssemblyDirectory at offset 8+ptr_size+4+padding (pointer) = null
        // Compute offsets based on ACTCTXW layout
        const lp_resource_name_off = @offsetOf(win.ACTCTXW, "lpResourceName");
        const h_module_off = @offsetOf(win.ACTCTXW, "hModule");
        // lpResourceName = MAKEINTRESOURCE(1) = 1
        @as(*align(1) usize, @ptrCast(&actctx_bytes[lp_resource_name_off])).* = 1;
        // hModule = base address
        @as(*align(1) usize, @ptrCast(&actctx_bytes[h_module_off])).* = @intFromPtr(self.addr_alloc);
        _ = ptr_size;

        const handle = create_act_ctx(@ptrCast(&actctx_bytes));
        const INVALID_HANDLE: usize = @as(usize, @bitCast(@as(isize, -1)));
        if (handle == null or @intFromPtr(handle.?) == INVALID_HANDLE) return null;

        var cookie: usize = 0;
        if (activate_act_ctx(handle, &cookie) == 0) {
            // Release
            const release_fn_ptr = win.GetProcAddress(@ptrCast(kernel32), "ReleaseActCtx");
            if (release_fn_ptr) |rfp| {
                const release_fn: *const fn (?*anyopaque) callconv(.c) void = @ptrCast(rfp);
                release_fn(handle);
            }
            return null;
        }

        return SxsGuard{ .handle = handle.?, .cookie = cookie };
    }

    /// Deactivate and release an SxS context.
    fn deactivateSxsContext(_: *RunPE, guard: SxsGuard) void {
        const kernel32 = win.LoadLibraryA("kernel32.dll") orelse return;
        const deact_ptr = win.GetProcAddress(@ptrCast(kernel32), "DeactivateActCtx") orelse return;
        const deact: *const fn (u32, usize) callconv(.c) i32 = @ptrCast(deact_ptr);
        _ = deact(0, guard.cookie);

        const release_ptr = win.GetProcAddress(@ptrCast(kernel32), "ReleaseActCtx") orelse return;
        const release: *const fn (?*anyopaque) callconv(.c) void = @ptrCast(release_ptr);
        release(guard.handle);
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

    /// Run the PE file with arguments.
    /// For .NET assemblies, args are passed to Main(string[]).
    /// For native PEs, args are passed by patching the PEB CommandLine.
    pub fn runWithArgs(self: *RunPE, args: []const []const u8) !void {
        try self.allocateMemory();
        defer {
            self.unregisterExceptionTable();
            _ = win.VirtualFree(self.addr_alloc, 0, win.MEM_RELEASE);
        }
        try self.copyHeaders();
        try self.get_nt_header();

        if (build_options.dotnet and utils.is_dotnet_assembly(self.ntheaders)) {
            try dotnet.executeDotNetAssembly(self.buffer, args);
        } else {
            try self.validateArchitecture();

            // Zero bound imports to prevent stale pre-resolved addresses
            debugLog("[runpe] Zeroing bound imports directory\n", .{});
            self.zeroBoundImportDirectory();

            debugLog("[runpe] Writing sections\n", .{});
            try self.write_sections();

            debugLog("[runpe] Resolving imports\n", .{});
            try self.write_import_table();

            debugLog("[runpe] Applying base relocations\n", .{});
            try self.fix_base_relocations();

            debugLog("[runpe] Resolving delayed imports\n", .{});
            try self.writeDelayedImportTable();

            debugLog("[runpe] Registering exception table\n", .{});
            try self.registerExceptionTable();

            // Initialize security cookie (__security_cookie for /GS)
            debugLog("[runpe] Initializing security cookie\n", .{});
            self.initializeSecurityCookie();

            // Setup CFG (Control Flow Guard)
            debugLog("[runpe] Setting up CFG\n", .{});
            self.setupCfg();

            debugLog("[runpe] Applying memory protections\n", .{});
            try self.changeMemoryProtection();

            // Activate SxS context for GUI PEs with manifests
            debugLog("[runpe] Activating SxS context\n", .{});
            const sxs_guard = self.activateSxsContext();

            debugLog("[runpe] Processing TLS callbacks\n", .{});
            try self.processTlsCallbacks();

            // Patch PEB command line so GetCommandLineW() returns our args
            var cmd_buf: [4096]u16 = undefined;
            var saved_cmd: ?SavedCommandLine = null;
            if (args.len > 0) {
                const count = buildWideCommandLine(args, &cmd_buf, cmd_buf.len);
                saved_cmd = patchPebCommandLine(&cmd_buf, count);
            }
            defer if (saved_cmd) |s| restorePebCommandLine(s);

            debugLog("[runpe] Executing PE\n", .{});
            try self.executeLoadedPE();

            // Deactivate SxS context
            if (sxs_guard) |guard| {
                debugLog("[runpe] Deactivating SxS context\n", .{});
                self.deactivateSxsContext(guard);
            }
        }
    }
};

// ============================================================================
// PEB command line patching (native PE argument passing)
// ============================================================================

const SavedCommandLine = struct {
    length: u16,
    maximum_length: u16,
    buffer: ?[*]u16,
};

/// Builds a quoted UTF-16 command line from args into a caller-provided buffer.
/// Returns the number of u16 units written (including null terminator).
pub fn buildWideCommandLine(args: []const []const u8, buf: [*]u16, buf_len: usize) usize {
    var pos: usize = 0;
    for (args, 0..) |arg, i| {
        if (i > 0 and pos < buf_len) {
            buf[pos] = ' ';
            pos += 1;
        }
        if (pos < buf_len) {
            buf[pos] = '"';
            pos += 1;
        }
        for (arg) |byte| {
            if (pos < buf_len) {
                buf[pos] = @as(u16, byte);
                pos += 1;
            }
        }
        if (pos < buf_len) {
            buf[pos] = '"';
            pos += 1;
        }
    }
    if (pos < buf_len) {
        buf[pos] = 0;
        pos += 1;
    }
    return pos;
}

/// Patches PEB CommandLine, returns saved state.
fn patchPebCommandLine(wide_buf: [*]u16, char_count: usize) SavedCommandLine {
    const peb = std.os.windows.peb();
    const cl = &peb.ProcessParameters.CommandLine;
    const saved = SavedCommandLine{
        .length = cl.Length,
        .maximum_length = cl.MaximumLength,
        .buffer = cl.Buffer,
    };
    const byte_len: u16 = @intCast((char_count - 1) * 2); // exclude null terminator
    cl.Length = byte_len;
    cl.MaximumLength = @intCast(char_count * 2);
    cl.Buffer = wide_buf;
    return saved;
}

/// Restores PEB CommandLine from saved state.
fn restorePebCommandLine(saved: SavedCommandLine) void {
    const peb = std.os.windows.peb();
    const cl = &peb.ProcessParameters.CommandLine;
    cl.Length = saved.length;
    cl.MaximumLength = saved.maximum_length;
    cl.Buffer = saved.buffer;
}

// ============================================================================
// Export table resolution (standalone utilities)
// ============================================================================

// ============================================================================
// Forwarded exports resolution
// ============================================================================

/// Resolve a forwarded export (e.g. "NTDLL.RtlAllocateHeap" or "NTDLL.#123").
fn resolveForwardedExport(base: [*]const u8, func_rva: usize) ?*anyopaque {
    const forward_str: [*:0]const u8 = @ptrCast(base + func_rva);
    const fwd = std.mem.sliceTo(forward_str, 0);

    const dot_pos = std.mem.indexOfScalar(u8, fwd, '.') orelse return null;
    const dll_part = fwd[0..dot_pos];
    const func_part = fwd[dot_pos + 1 ..];

    // Build DLL name with .dll suffix
    var dll_buf: [256:0]u8 = undefined;
    if (dll_part.len + 4 >= dll_buf.len) return null;
    @memcpy(dll_buf[0..dll_part.len], dll_part);
    @memcpy(dll_buf[dll_part.len..][0..4], ".dll");
    dll_buf[dll_part.len + 4] = 0;

    const dll_handle = win.LoadLibraryA(@ptrCast(&dll_buf)) orelse return null;

    // Check for ordinal forward: "#123"
    if (func_part.len > 0 and func_part[0] == '#') {
        var ordinal: u16 = 0;
        for (func_part[1..]) |b| {
            if (b >= '0' and b <= '9') {
                ordinal = ordinal *% 10 +% @as(u16, b - '0');
            } else break;
        }
        return @ptrCast(win.GetProcAddress(@ptrCast(dll_handle), @ptrFromInt(@as(usize, ordinal))));
    }

    // Name-based forward
    var func_buf: [256:0]u8 = undefined;
    if (func_part.len >= func_buf.len) return null;
    @memcpy(func_buf[0..func_part.len], func_part);
    func_buf[func_part.len] = 0;
    return @ptrCast(win.GetProcAddress(@ptrCast(dll_handle), @ptrCast(&func_buf)));
}

/// Resolve an export by name from a loaded PE image.
/// Handles forwarded exports by loading the target DLL.
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

            if (func_rva >= export_dir_start and func_rva < export_dir_end) {
                // Forwarded export — resolve it
                return resolveForwardedExport(base, func_rva);
            }
            return @ptrFromInt(@intFromPtr(base) + func_rva);
        }
    }
    return null;
}

/// Resolve an export by ordinal from a loaded PE image.
/// Handles forwarded exports by loading the target DLL.
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

    if (func_rva >= export_dir_start and func_rva < export_dir_end) {
        // Forwarded export — resolve it
        return resolveForwardedExport(base, func_rva);
    }
    return @ptrFromInt(@intFromPtr(base) + func_rva);
}

// ============================================================================
// API Set Schema resolution
// ============================================================================

/// Resolve an API set DLL name (e.g. "api-ms-win-core-heap-l1-1-0.dll") to its
/// host DLL using the PEB ApiSetMap. Writes the result into `out_buf`.
/// Returns a null-terminated slice, or null if not an API set or resolution fails.
pub fn resolveApiSet(dll_name: []const u8, out_buf: []u8) ?[]const u8 {
    if (dll_name.len < 4) return null;

    // Check prefix: "api-" or "ext-" (case-insensitive)
    const p0 = dll_name[0] | 0x20;
    const p1 = dll_name[1] | 0x20;
    const p2 = dll_name[2] | 0x20;
    const p3 = dll_name[3];
    const is_api = (p0 == 'a' and p1 == 'p' and p2 == 'i' and p3 == '-');
    const is_ext = (p0 == 'e' and p1 == 'x' and p2 == 't' and p3 == '-');
    if (!is_api and !is_ext) return null;

    // Read PEB -> ApiSetMap
    const peb = std.os.windows.peb();
    const peb_bytes: [*]const u8 = @ptrCast(peb);
    const map_off: usize = if (@sizeOf(usize) == 8) 0x68 else 0x38;
    const api_set_map: *const API_SET_NAMESPACE = @ptrCast(@alignCast(
        @as(*const *const API_SET_NAMESPACE, @ptrCast(@alignCast(peb_bytes + map_off))).*,
    ));

    if (api_set_map.Version < 2) return null;

    // Strip ".dll" suffix
    var name_no_ext = dll_name;
    if (dll_name.len > 4) {
        const last4 = dll_name[dll_name.len - 4 ..];
        if ((last4[0] | 0x20) == '.' and (last4[1] | 0x20) == 'd' and
            (last4[2] | 0x20) == 'l' and (last4[3] | 0x20) == 'l')
        {
            name_no_ext = dll_name[0 .. dll_name.len - 4];
        }
    }

    // Strip last "-N" segment for lookup key
    var lookup_key = name_no_ext;
    if (std.mem.lastIndexOfScalar(u8, name_no_ext, '-')) |pos| {
        lookup_key = name_no_ext[0..pos];
    }

    // Linear search through namespace entries
    const base: [*]const u8 = @ptrCast(api_set_map);
    for (0..api_set_map.Count) |i| {
        const entry: *const API_SET_NAMESPACE_ENTRY = @ptrCast(@alignCast(
            base + api_set_map.EntryOffset + i * @sizeOf(API_SET_NAMESPACE_ENTRY),
        ));

        const entry_name_ptr: [*]const u16 = @ptrCast(@alignCast(base + entry.NameOffset));
        const entry_name_len = entry.HashedLength / 2;

        if (entry_name_len != lookup_key.len) continue;

        var matched = true;
        for (0..entry_name_len) |j| {
            const wide_char: u8 = @truncate(entry_name_ptr[j]);
            if ((wide_char | 0x20) != (lookup_key[j] | 0x20)) {
                matched = false;
                break;
            }
        }

        if (!matched) continue;

        if (entry.ValueCount == 0) return null;

        const value: *const API_SET_VALUE_ENTRY = @ptrCast(@alignCast(
            base + entry.ValueOffset,
        ));

        if (value.ValueLength == 0) return null;

        // Convert wide host DLL name to ASCII
        const host_ptr: [*]const u16 = @ptrCast(@alignCast(base + value.ValueOffset));
        const host_len = value.ValueLength / 2;
        if (host_len + 1 > out_buf.len) return null;

        var actual_len: usize = 0;
        for (0..host_len) |j| {
            const ch = host_ptr[j];
            if (ch == 0) break;
            out_buf[actual_len] = @truncate(ch);
            actual_len += 1;
        }
        out_buf[actual_len] = 0;
        return out_buf[0..actual_len];
    }

    return null;
}
