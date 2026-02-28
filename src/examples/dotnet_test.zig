const pe = @import("pe");

pub fn main() !void {
    var loader = pe.RunPE.init(@embedFile("bin/hello_dot_net.exe"));
    try loader.runWithArgs(&.{ "hello", "from", "zig-pe" });
}
