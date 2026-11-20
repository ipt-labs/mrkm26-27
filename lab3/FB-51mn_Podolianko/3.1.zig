//usr/bin/env zig run "$0" -- "$@"; exit
const std = @import("std");
const print = std.debug.print;
const X25519 = std.crypto.dh.X25519;

const Command = enum { generate, compute };
pub fn main(init: std.process.Init) !void {
    const args = init.minimal.args;
    if (args.vector.len < 2) {
        print("Provide command: ", .{});
        for (@typeInfo(Command).@"enum".field_names) |command| print("{s} ", .{command});
        print("\n", .{});
        return;
    }
    const command_string: []const u8 = std.mem.span(args.vector[1]);
    if (std.meta.stringToEnum(Command, command_string)) |command|
        switch (command) {
            .generate => {
                const keypair = X25519.KeyPair.generate(init.io);
                print("Public key: {x}\nPrivate key: {x}\n", .{ keypair.public_key, keypair.secret_key });
            },
            .compute => {
                check_args_count: {
                    switch (args.vector.len) {
                        0...2 => print("Provide (other party's) public key\n", .{}),
                        3 => print("Provide (our) secret key\n", .{}),
                        4 => break :check_args_count,
                        else => print("Extra arguments\n", .{}),
                    }
                    return;
                }
                var public: [X25519.public_length]u8 = undefined;
                var secret: [X25519.secret_length]u8 = undefined;
                std.debug.assert((try std.fmt.hexToBytes(&public, std.mem.span(args.vector[2]))).len == public.len);
                std.debug.assert((try std.fmt.hexToBytes(&secret, std.mem.span(args.vector[3]))).len == secret.len);
                const shared = try X25519.scalarmult(secret, public);
                print("Shared secret: {x}\n", .{shared});
            },
        };
}
