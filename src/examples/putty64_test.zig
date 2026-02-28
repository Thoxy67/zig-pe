const std = @import("std");
const pe = @import("pe");

pub fn main() !void {
    // Use embed PE
    var loader = pe.RunPE.init(@embedFile("bin/putty_x64.exe"));
    try loader.run();
}
