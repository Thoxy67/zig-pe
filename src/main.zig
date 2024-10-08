const std = @import("std");
const pe = @import("pe.zig");

pub fn main() !void {

    // Use local PE
    // var gpa = std.heap.GeneralPurposeAllocator(.{}){};
    // defer _ = gpa.deinit();
    // const allocator = gpa.allocator();
    // const file_name = "src/bin/putty.exe";
    // const file_content = try std.fs.cwd().readFileAlloc(allocator, file_name, std.math.maxInt(usize));
    // defer allocator.free(file_content);
    // try pe.RunPE.init(file_content).run();

    // Use embed PE
    try pe.RunPE.init(@embedFile("bin/putty.exe")).run();
}
