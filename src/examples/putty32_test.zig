const std = @import("std");
const pe = @import("pe");

pub fn main() !void {
    // Use embed PE
    var loader = pe.RunPE.init(@embedFile("bin/putty_x86.exe"));
    try loader.run();
}
