//usr/bin/env zig run "$0" -- "$@"; exit
const std = @import("std");
const print = std.debug.print;
const Ed25519 = std.crypto.sign.Ed25519;
const Command = enum { generate, sign, verify };

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
            .generate => try generate(init.io),
            .sign => {
                check_arg_count: {
                    switch (args.vector.len) {
                        4 => break :check_arg_count,
                        0...2 => print("Provide secret key in hex\n", .{}),
                        3 => print("Provide message to sign\n", .{}),
                        else => print("Extra arguments\n", .{}),
                    }
                    return;
                }
                const key_hex: []const u8 = std.mem.span(args.vector[2]);
                const message: []const u8 = std.mem.span(args.vector[3]);
                var secret_key_bytes: [Ed25519.SecretKey.encoded_length]u8 = undefined;
                std.debug.assert((try std.fmt.hexToBytes(&secret_key_bytes, key_hex)).len == secret_key_bytes.len);
                try sign(
                    init.io,
                    try Ed25519.KeyPair.fromSecretKey(try Ed25519.SecretKey.fromBytes(secret_key_bytes)),
                    message,
                );
            },
            .verify => {
                check_arg_count: {
                    switch (args.vector.len) {
                        5 => break :check_arg_count,
                        0...2 => print("Provide public key in hex\n", .{}),
                        3 => print("Provide message to verify\n", .{}),
                        4 => print("Provide signature to verify\n", .{}),
                        else => print("Extra arguments\n", .{}),
                    }
                    return;
                }
                const public_key_hex: []const u8 = std.mem.span(args.vector[2]);
                var public_key_bytes: [Ed25519.PublicKey.encoded_length]u8 = undefined;
                std.debug.assert((try std.fmt.hexToBytes(&public_key_bytes, public_key_hex)).len == public_key_bytes.len);
                const public_key = try Ed25519.PublicKey.fromBytes(public_key_bytes);
                const message: []const u8 = std.mem.span(args.vector[3]);
                const signature_hex: []const u8 = std.mem.span(args.vector[4]);
                try verify(public_key, message, signature_hex);
            },
        }
    else
        print("Unknown command {s}\n", .{command_string});
}

fn generate(io: std.Io) !void {
    const keypair = std.crypto.sign.Ed25519.KeyPair.generate(io);
    const public_key = keypair.public_key.toBytes();
    const private_key = keypair.secret_key.toBytes();
    print("Public key: {x}\n", .{public_key});
    print("Private key: {x}\n", .{private_key});
}

fn sign(io: std.Io, kp: Ed25519.KeyPair, message: []const u8) !void {
    var signer = try kp.signer(null, io); // non-deterministic signatures with random
    signer.update(message);
    const signature = signer.finalize();
    const signature_bytes = signature.toBytes();
    print("Signature: {x}\n", .{signature_bytes});
}

fn verify(pk: Ed25519.PublicKey, message: []const u8, signature_hex: []const u8) !void {
    var signature_bytes: [Ed25519.Signature.encoded_length]u8 = undefined;
    std.debug.assert((try std.fmt.hexToBytes(&signature_bytes, signature_hex)).len == signature_bytes.len);
    const signature = Ed25519.Signature.fromBytes(signature_bytes);
    var verifier = try signature.verifier(pk);
    verifier.update(message);
    verifier.verifyStrict() catch |err| {
        if (err == error.SignatureVerificationFailed) {
            print(("INVALID SIGNATURE!\n"), .{});
            return err;
        }
    };
    print("Signature valid!\n", .{});
}
