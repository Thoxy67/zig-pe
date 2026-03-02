const std = @import("std");
const pe = @import("pe");

pub fn main(init: std.process.Init) !void {
    var loader = pe.RunPE.init(@embedFile("bin/putty_x86.exe"));

    var args_list: std.ArrayListUnmanaged([]const u8) = .empty;
    defer args_list.deinit(init.gpa);

    var it = try std.process.Args.iterateAllocator(init.minimal.args, init.gpa);
    defer it.deinit();
    _ = it.skip(); // skip program name
    while (it.next()) |arg| {
        try args_list.append(init.gpa, arg);
    }

    try loader.runWithArgs(args_list.items);
}
