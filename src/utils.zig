const std = @import("std");
const win = @cImport(@cInclude("windows.h"));
const builtin = @import("builtin");

/// Check if the PE file is a .NET assembly
pub fn is_dotnet_assembly(nt_headers: *win.IMAGE_NT_HEADERS) bool {
    const data_directory = &nt_headers.OptionalHeader.DataDirectory[win.IMAGE_DIRECTORY_ENTRY_COM_DESCRIPTOR];
    return data_directory.VirtualAddress != 0;
}

/// Detect if the target pe platform is 32 or 64bit
pub fn detect_platform(bytes: []const u8) !u32 {
    const pe_offset = std.mem.readVarInt(u32, bytes[0x3C..0x40], .little);
    if (bytes.len < pe_offset + 6) return error.InvalidMachineTypePE;
    const machine = std.mem.readVarInt(u16, bytes[pe_offset + 4 .. pe_offset + 6], .little);
    return switch (machine) {
        0x014c => 32, // IMAGE_FILE_MACHINE_I386
        0x0200 => 64, // IMAGE_FILE_MACHINE_IA64
        0x8664 => 64, // IMAGE_FILE_MACHINE_AMD64
        else => error.NotSupportedPlatform,
    };
}

/// Wait for the created thread to complete execution
pub fn waitForThreadCompletion(thread_handle: win.HANDLE) !win.DWORD {
    const wait_result = std.os.windows.kernel32.WaitForSingleObject(thread_handle.?, std.os.windows.INFINITE);
    switch (wait_result) {
        std.os.windows.WAIT_OBJECT_0 => {},
        std.os.windows.WAIT_TIMEOUT => {},
        std.os.windows.WAIT_FAILED => return error.WaitFailed,
        else => return error.UnexpectedWaitResult,
    }
    var exit_code: win.DWORD = undefined;
    return if (win.GetExitCodeThread(thread_handle, &exit_code) == 0) error.GetExitCodeFailed else exit_code;
}
