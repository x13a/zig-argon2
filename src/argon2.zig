// https://tools.ietf.org/id/draft-irtf-cfrg-argon2-13.html
// https://github.com/golang/crypto/tree/master/argon2
// https://github.com/P-H-C/phc-winner-argon2

const std = @import("std");
const blake2 = crypto.hash.blake2;
const crypto = std.crypto;
const math = std.math;
const mem = std.mem;
const phc_format = pwhash.phc_format;
const pwhash = crypto.pwhash;

const Thread = std.Thread;
const Blake2b128 = blake2.Blake2b128;
const Blake2b160 = blake2.Blake2b160;
const Blake2b192 = blake2.Blake2b(192);
const Blake2b256 = blake2.Blake2b256;
const Blake2b384 = blake2.Blake2b384;
const Blake2b512 = blake2.Blake2b512;
const Blocks = std.ArrayListAligned([block_length]u64, 16);
const H0 = [Blake2b512.digest_length + 8]u8;

const EncodingError = crypto.errors.EncodingError;
const KdfError = pwhash.KdfError || Thread.SpawnError;
const HasherError = pwhash.HasherError || KdfError;
const Error = pwhash.Error || HasherError;

const version = 0x13;
const block_length = 128;
const sync_points = 4;
const max_int = 0xffff_ffff;

const default_salt_len = 32;
const default_hash_len = 32;
const max_salt_len = 64;
const max_hash_len = 64;

/// Argon2 type
///
/// Argon2d is faster and uses data-depending memory access, which makes it highly resistant 
/// against GPU cracking attacks and suitable for applications with no threats from side-channel 
/// timing attacks (eg. cryptocurrencies).
///
/// Argon2i instead uses data-independent memory access, which is preferred for password 
/// hashing and password-based key derivation, but it is slower as it makes more passes over 
/// the memory to protect from tradeoff attacks.
///
/// Argon2id is a hybrid of Argon2i and Argon2d, using a combination of data-depending and 
/// data-independent memory accesses, which gives some of Argon2i's resistance to side-channel 
/// cache timing attacks and much of Argon2d's resistance to GPU cracking attacks.
pub const Mode = enum(u2) {
    const Self = @This();

    argon2d,
    argon2i,
    argon2id,

    fn toString(self: Self) []const u8 {
        return switch (self) {
            Self.argon2d => "argon2d",
            Self.argon2i => "argon2i",
            Self.argon2id => "argon2id",
        };
    }

    fn fromString(str: []const u8) EncodingError!Self {
        if (mem.eql(u8, str, "argon2d")) {
            return Self.argon2d;
        } else if (mem.eql(u8, str, "argon2i")) {
            return Self.argon2i;
        } else if (mem.eql(u8, str, "argon2id")) {
            return Self.argon2id;
        } else {
            return EncodingError.InvalidEncoding;
        }
    }
};

/// Argon2 parameters
///
/// A [t]ime cost, which defines the amount of computation realized and therefore the execution 
/// time, given in number of iterations.
///
/// A [m]emory cost, which defines the memory usage, given in kibibytes.
///
/// A [p]arallelism degree, which defines the number of parallel threads.
///
/// The [secret] parameter, which is used for keyed hashing. This allows a secret key to be input 
/// at hashing time (from some external location) and be folded into the value of the hash. This 
/// means that even if your salts and hashes are compromised, an attacker cannot brute-force to 
/// find the password without the key.
///
/// The [ad] parameter, which is used to fold any additional data into the hash value. Functionally, 
/// this behaves almost exactly like the secret or salt parameters; the ad parameter is folding 
/// into the value of the hash. However, this parameter is used for different data. The salt 
/// should be a random string stored alongside your password. The secret should be a random key 
/// only usable at hashing time. The ad is for any other data.
pub const Params = struct {
    const Self = @This();

    t: u32,
    m: u32,
    p: u8,
    secret: ?[]const u8 = null,
    ad: ?[]const u8 = null,

    /// Baseline parameters for interactive logins using argon2i type
    pub const interactive_2i = Self.fromLimits(4, 33554432);
    /// Baseline parameters for .. using argon2i type
    pub const moderate_2i = Self.fromLimits(6, 134217728);
    /// Baseline parameters for offline usage using argon2i type
    pub const sensitive_2i = Self.fromLimits(8, 536870912);

    /// Baseline parameters for interactive logins using argon2id type
    pub const interactive_2id = Self.fromLimits(2, 67108864);
    /// Baseline parameters for .. using argon2id type
    pub const moderate_2id = Self.fromLimits(3, 268435456);
    /// Baseline parameters for offline usage using argon2id type
    pub const sensitive_2id = Self.fromLimits(4, 1073741824);

    /// Create parameters from ops and mem limits
    pub fn fromLimits(ops_limit: u32, mem_limit: usize) Self {
        const m = mem_limit / 1024;
        std.assert.debug(m <= max_int);
        return .{ .t = ops_limit, .m = @intCast(u32, m), .p = 1 };
    }
};

fn initHash(
    password: []const u8,
    salt: []const u8,
    params: Params,
    dk_len: usize,
    mode: Mode,
) H0 {
    var h0: H0 = undefined;
    var parameters: [24]u8 = undefined;
    var tmp: [4]u8 = undefined;
    var b2 = Blake2b512.init(.{});
    mem.writeIntLittle(u32, parameters[0..4], params.p);
    mem.writeIntLittle(u32, parameters[4..8], @intCast(u32, dk_len));
    mem.writeIntLittle(u32, parameters[8..12], params.m);
    mem.writeIntLittle(u32, parameters[12..16], params.t);
    mem.writeIntLittle(u32, parameters[16..20], version);
    mem.writeIntLittle(u32, parameters[20..24], @enumToInt(mode));
    b2.update(&parameters);
    mem.writeIntLittle(u32, &tmp, @intCast(u32, password.len));
    b2.update(&tmp);
    b2.update(password);
    mem.writeIntLittle(u32, &tmp, @intCast(u32, salt.len));
    b2.update(&tmp);
    b2.update(salt);
    const secret = params.secret orelse "";
    std.debug.assert(secret.len <= max_int);
    mem.writeIntLittle(u32, &tmp, @intCast(u32, secret.len));
    b2.update(&tmp);
    b2.update(secret);
    const ad = params.ad orelse "";
    std.debug.assert(ad.len <= max_int);
    mem.writeIntLittle(u32, &tmp, @intCast(u32, ad.len));
    b2.update(&tmp);
    b2.update(ad);
    b2.final(h0[0..Blake2b512.digest_length]);
    return h0;
}

fn blake2bHash(out: []u8, in: []const u8, comptime hasher: type) void {
    var b2 = hasher.init(.{});

    var buffer: [Blake2b512.digest_length]u8 = undefined;
    mem.writeIntLittle(u32, buffer[0..4], @intCast(u32, out.len));
    b2.update(buffer[0..4]);
    b2.update(in);

    if (out.len <= Blake2b512.digest_length) {
        b2.final(out[0..hasher.digest_length]);
        return;
    }

    std.debug.assert(out.len % Blake2b512.digest_length == 0);

    b2.final(buffer[0..hasher.digest_length]);
    b2 = hasher.init(.{});
    mem.copy(u8, out, buffer[0..32]);
    var out_tmp = out[32..];
    while (out_tmp.len > Blake2b512.digest_length) : ({
        out_tmp = out_tmp[32..];
        b2 = hasher.init(.{});
    }) {
        b2.update(&buffer);
        b2.final(buffer[0..hasher.digest_length]);
        mem.copy(u8, out_tmp, buffer[0..32]);
    }

    b2.update(&buffer);
    b2.final(out_tmp[0..hasher.digest_length]);
}

fn initBlocks(
    blocks: *Blocks,
    h0: *H0,
    memory: u32,
    threads: u32,
) void {
    var block0: [1024]u8 = undefined;
    var lane: u32 = 0;
    while (lane < threads) : (lane += 1) {
        const j = lane * (memory / threads);
        mem.writeIntLittle(u32, h0[Blake2b512.digest_length + 4 ..][0..4], lane);

        mem.writeIntLittle(u32, h0[Blake2b512.digest_length..][0..4], 0);
        blake2bHash(&block0, h0, Blake2b512);
        for (blocks.items[j + 0]) |*v, i| {
            v.* = mem.readIntLittle(u64, block0[i * 8 ..][0..8]);
        }

        mem.writeIntLittle(u32, h0[Blake2b512.digest_length..][0..4], 1);
        blake2bHash(&block0, h0, Blake2b512);
        for (blocks.items[j + 1]) |*v, i| {
            v.* = mem.readIntLittle(u64, block0[i * 8 ..][0..8]);
        }
    }
}

fn processBlocks(
    blocks: *Blocks,
    time: u32,
    memory: u32,
    threads: u32,
    mode: Mode,
) Thread.SpawnError!void {
    const lanes = memory / threads;
    const segments = lanes / sync_points;

    if (threads == 1) {
        processBlocksSt(blocks, time, memory, threads, mode, lanes, segments);
    } else {
        try processBlocksMt(blocks, time, memory, threads, mode, lanes, segments);
    }
}

fn processBlocksSt(
    blocks: *Blocks,
    time: u32,
    memory: u32,
    threads: u32,
    mode: Mode,
    lanes: u32,
    segments: u32,
) void {
    var n: u32 = 0;
    while (n < time) : (n += 1) {
        var slice: u32 = 0;
        while (slice < sync_points) : (slice += 1) {
            var lane: u32 = 0;
            while (lane < threads) : (lane += 1) {
                processSegment(blocks, time, memory, threads, mode, lanes, segments, n, slice, lane);
            }
        }
    }
}

fn processBlocksMt(
    blocks: *Blocks,
    time: u32,
    memory: u32,
    threads: u32,
    mode: Mode,
    lanes: u32,
    segments: u32,
) Thread.SpawnError!void {
    var threads_arr: [256]Thread = undefined;
    var n: u32 = 0;
    while (n < time) : (n += 1) {
        var slice: u32 = 0;
        while (slice < sync_points) : (slice += 1) {
            var lane: u32 = 0;
            while (lane < threads) : (lane += 1) {
                const thread = try Thread.spawn(.{}, processSegment, .{
                    blocks, time, memory, threads, mode, lanes, segments, n, slice, lane,
                });
                threads_arr[lane] = thread;
            }
            lane = 0;
            while (lane < threads) : (lane += 1) {
                threads_arr[lane].join();
            }
        }
    }
}

fn processSegment(
    blocks: *Blocks,
    time: u32,
    memory: u32,
    threads: u32,
    mode: Mode,
    lanes: u32,
    segments: u32,
    n: u32,
    slice: u32,
    lane: u32,
) void {
    var addresses align(16) = [_]u64{0} ** block_length;
    var in align(16) = [_]u64{0} ** block_length;
    var zero align(16) = [_]u64{0} ** block_length;
    if (mode == .argon2i or (mode == .argon2id and n == 0 and slice < sync_points / 2)) {
        in[0] = n;
        in[1] = lane;
        in[2] = slice;
        in[3] = memory;
        in[4] = time;
        in[5] = @enumToInt(mode);
    }
    var index: u32 = 0;
    if (n == 0 and slice == 0) {
        index = 2;
        if (mode == .argon2i or mode == .argon2id) {
            in[6] += 1;
            processBlock(&addresses, &in, &zero);
            processBlock(&addresses, &addresses, &zero);
        }
    }
    var offset = lane * lanes + slice * segments + index;
    var random: u64 = 0;
    while (index < segments) : ({
        index += 1;
        offset += 1;
    }) {
        var prev = offset -% 1;
        if (index == 0 and slice == 0) {
            prev +%= lanes;
        }
        if (mode == .argon2i or (mode == .argon2id and n == 0 and slice < sync_points / 2)) {
            if (index % block_length == 0) {
                in[6] += 1;
                processBlock(&addresses, &in, &zero);
                processBlock(&addresses, &addresses, &zero);
            }
            random = addresses[index % block_length];
        } else {
            random = blocks.items[prev][0];
        }
        const new_offset = indexAlpha(random, lanes, segments, threads, n, slice, lane, index);
        processBlockXor(&blocks.items[offset], &blocks.items[prev], &blocks.items[new_offset]);
    }
}

fn processBlock(
    out: *align(16) [block_length]u64,
    in1: *align(16) const [block_length]u64,
    in2: *align(16) const [block_length]u64,
) void {
    processBlockGeneric(out, in1, in2, false);
}

fn processBlockXor(
    out: *[block_length]u64,
    in1: *const [block_length]u64,
    in2: *const [block_length]u64,
) void {
    processBlockGeneric(out, in1, in2, true);
}

fn processBlockGeneric(
    out: *[block_length]u64,
    in1: *const [block_length]u64,
    in2: *const [block_length]u64,
    xor: bool,
) void {
    var t: [block_length]u64 = undefined;
    for (t) |*v, i| {
        v.* = in1[i] ^ in2[i];
    }
    var i: usize = 0;
    while (i < block_length) : (i += 16) {
        blamkaGeneric(
            &t[i + 0],
            &t[i + 1],
            &t[i + 2],
            &t[i + 3],
            &t[i + 4],
            &t[i + 5],
            &t[i + 6],
            &t[i + 7],
            &t[i + 8],
            &t[i + 9],
            &t[i + 10],
            &t[i + 11],
            &t[i + 12],
            &t[i + 13],
            &t[i + 14],
            &t[i + 15],
        );
    }
    i = 0;
    while (i < block_length / 8) : (i += 2) {
        blamkaGeneric(
            &t[i],
            &t[i + 1],
            &t[16 + i],
            &t[16 + i + 1],
            &t[32 + i],
            &t[32 + i + 1],
            &t[48 + i],
            &t[48 + i + 1],
            &t[64 + i],
            &t[64 + i + 1],
            &t[80 + i],
            &t[80 + i + 1],
            &t[96 + i],
            &t[96 + i + 1],
            &t[112 + i],
            &t[112 + i + 1],
        );
    }
    if (xor) {
        for (t) |v, j| {
            out[j] ^= in1[j] ^ in2[j] ^ v;
        }
    } else {
        for (t) |v, j| {
            out[j] = in1[j] ^ in2[j] ^ v;
        }
    }
}

const QuarterRound = struct { a: usize, b: usize, c: usize, d: usize };

fn Rp(a: usize, b: usize, c: usize, d: usize) QuarterRound {
    return .{ .a = a, .b = b, .c = c, .d = d };
}

fn fBlaMka(x: u64, y: u64) u64 {
    const xy = (x & 0xffff_ffff) * (y & 0xffff_ffff);
    return x +% y +% 2 *% xy;
}

fn blamkaGeneric(
    t00: *u64,
    t01: *u64,
    t02: *u64,
    t03: *u64,
    t04: *u64,
    t05: *u64,
    t06: *u64,
    t07: *u64,
    t08: *u64,
    t09: *u64,
    t10: *u64,
    t11: *u64,
    t12: *u64,
    t13: *u64,
    t14: *u64,
    t15: *u64,
) void {
    var x = [_]u64{
        t00.*, t01.*, t02.*, t03.*,
        t04.*, t05.*, t06.*, t07.*,
        t08.*, t09.*, t10.*, t11.*,
        t12.*, t13.*, t14.*, t15.*,
    };
    const rounds = comptime [_]QuarterRound{
        Rp(0, 4, 8, 12),
        Rp(1, 5, 9, 13),
        Rp(2, 6, 10, 14),
        Rp(3, 7, 11, 15),
        Rp(0, 5, 10, 15),
        Rp(1, 6, 11, 12),
        Rp(2, 7, 8, 13),
        Rp(3, 4, 9, 14),
    };
    inline for (rounds) |r| {
        x[r.a] = fBlaMka(x[r.a], x[r.b]);
        x[r.d] = math.rotr(u64, x[r.d] ^ x[r.a], 32);
        x[r.c] = fBlaMka(x[r.c], x[r.d]);
        x[r.b] = math.rotr(u64, x[r.b] ^ x[r.c], 24);
        x[r.a] = fBlaMka(x[r.a], x[r.b]);
        x[r.d] = math.rotr(u64, x[r.d] ^ x[r.a], 16);
        x[r.c] = fBlaMka(x[r.c], x[r.d]);
        x[r.b] = math.rotr(u64, x[r.b] ^ x[r.c], 63);
    }
    t00.* = x[0];
    t01.* = x[1];
    t02.* = x[2];
    t03.* = x[3];
    t04.* = x[4];
    t05.* = x[5];
    t06.* = x[6];
    t07.* = x[7];
    t08.* = x[8];
    t09.* = x[9];
    t10.* = x[10];
    t11.* = x[11];
    t12.* = x[12];
    t13.* = x[13];
    t14.* = x[14];
    t15.* = x[15];
}

fn extractKey(
    blocks: *Blocks,
    memory: u32,
    threads: u32,
    out: []u8,
    comptime hasher: ?type,
) void {
    const lanes = memory / threads;
    var lane: u32 = 0;
    while (lane < threads - 1) : (lane += 1) {
        for (blocks.items[(lane * lanes) + lanes - 1]) |v, i| {
            blocks.items[memory - 1][i] ^= v;
        }
    }
    var block: [1024]u8 = undefined;
    for (blocks.items[memory - 1]) |v, i| {
        mem.writeIntLittle(u64, block[i * 8 ..][0..8], v);
    }
    switch (out.len) {
        Blake2b512.digest_length => blake2bHash(out, &block, Blake2b512),
        Blake2b384.digest_length => blake2bHash(out, &block, Blake2b384),
        Blake2b256.digest_length => blake2bHash(out, &block, Blake2b256),
        Blake2b192.digest_length => blake2bHash(out, &block, Blake2b192),
        Blake2b160.digest_length => blake2bHash(out, &block, Blake2b160),
        Blake2b128.digest_length => blake2bHash(out, &block, Blake2b128),
        else => {
            if (out.len % Blake2b512.digest_length == 0) {
                blake2bHash(out, &block, Blake2b512);
            } else if (hasher) |h| {
                blake2bHash(out, &block, h);
            } else {
                unreachable;
            }
        },
    }
}

fn indexAlpha(
    rand: u64,
    lanes: u32,
    segments: u32,
    threads: u32,
    n: u32,
    slice: u32,
    lane: u32,
    index: u32,
) u32 {
    var ref_lane = @intCast(u32, rand >> 32) % threads;
    if (n == 0 and slice == 0) {
        ref_lane = lane;
    }
    var m = 3 * segments;
    var s = ((slice + 1) % sync_points) * segments;
    if (lane == ref_lane) {
        m += index;
    }
    if (n == 0) {
        m = slice * segments;
        s = 0;
        if (slice == 0 or lane == ref_lane) {
            m += index;
        }
    }
    if (index == 0 or lane == ref_lane) {
        m -= 1;
    }
    return phi(rand, m, s, ref_lane, lanes);
}

fn phi(
    rand: u64,
    m: u64,
    s: u64,
    lane: u32,
    lanes: u32,
) u32 {
    var p = rand & 0xffff_ffff;
    p = (p * p) >> 32;
    p = (p * m) >> 32;
    return lane * lanes + @intCast(u32, ((s + m - (p + 1)) % lanes));
}

/// Derives a key from the password, salt, and argon2 parameters.
///
/// The [hasher] is Blake2b(derived_key.len * 8). It is required when derived_key length 
/// not in [16, 20, 24, 32, 48, 64, l%64].
pub fn kdf(
    allocator: *mem.Allocator,
    derived_key: []u8,
    password: []const u8,
    salt: []const u8,
    params: Params,
    mode: Mode,
    comptime hasher: ?type,
) KdfError!void {
    if (derived_key.len < 4 or derived_key.len > max_int) return KdfError.OutputTooLong;
    if (password.len > max_int) return KdfError.WeakParameters;
    if (salt.len < 8 or salt.len > max_int) return KdfError.WeakParameters;
    if (params.t < 1 or params.p < 1) return KdfError.WeakParameters;

    if (hasher == null and
        derived_key.len != Blake2b128.digest_length and
        derived_key.len != Blake2b160.digest_length and
        derived_key.len != Blake2b192.digest_length and
        derived_key.len != Blake2b256.digest_length and
        derived_key.len != Blake2b384.digest_length and
        derived_key.len % Blake2b512.digest_length != 0) return KdfError.WeakParameters;

    var h0 = initHash(password, salt, params, derived_key.len, mode);
    const memory = math.max(
        params.m / (sync_points * params.p) * (sync_points * params.p),
        2 * sync_points * params.p,
    );

    var blocks = try Blocks.initCapacity(allocator, memory);
    defer blocks.deinit();

    blocks.appendNTimesAssumeCapacity([_]u64{0} ** block_length, memory);

    initBlocks(&blocks, &h0, memory, params.p);
    try processBlocks(&blocks, params.t, memory, params.p, mode);
    extractKey(&blocks, memory, params.p, derived_key, hasher);
}

const PhcFormatHasher = struct {
    const BinValue = phc_format.BinValue;

    const HashResult = struct {
        alg_id: []const u8,
        t: u32,
        m: u32,
        p: u8,
        salt: BinValue(max_salt_len),
        hash: BinValue(max_hash_len),
    };

    pub fn create(
        allocator: *mem.Allocator,
        password: []const u8,
        params: Params,
        mode: Mode,
        buf: []u8,
    ) HasherError![]const u8 {
        var salt: [default_salt_len]u8 = undefined;
        crypto.random.bytes(&salt);

        var hash: [default_hash_len]u8 = undefined;
        try kdf(allocator, &hash, password, &salt, params, mode, null);

        return phc_format.serialize(HashResult{
            .alg_id = mode.toString(),
            .t = params.t,
            .m = params.m,
            .p = params.p,
            .salt = try BinValue(max_salt_len).fromSlice(&salt),
            .hash = try BinValue(max_hash_len).fromSlice(&hash),
        }, buf);
    }

    pub fn verify(
        allocator: *mem.Allocator,
        str: []const u8,
        password: []const u8,
    ) HasherError!void {
        const hash_result = try phc_format.deserialize(HashResult, str);

        const mode = Mode.fromString(hash_result.alg_id) catch
            return HasherError.PasswordVerificationFailed;
        const params = Params{ .t = hash_result.t, .m = hash_result.m, .p = hash_result.p };

        const expected_hash = hash_result.hash.constSlice();
        var hash_buf: [max_hash_len]u8 = undefined;
        if (expected_hash.len > hash_buf.len) return HasherError.InvalidEncoding;
        var hash = hash_buf[0..expected_hash.len];

        try kdf(allocator, hash, password, hash_result.salt.constSlice(), params, mode, null);
        if (!mem.eql(u8, hash, expected_hash)) return HasherError.PasswordVerificationFailed;
    }
};

/// Options for hashing a password.
///
/// Allocator is required for argon2.
///
/// Only phc encoding is supported.
pub const HashOptions = struct {
    allocator: ?*mem.Allocator,
    kdf_params: Params,
    mode: Mode,
    encoding: pwhash.Encoding,
};

/// Compute a hash of a password using the argon2 key derivation function.
/// The function returns a string that includes all the parameters required for verification.
pub fn strHash(
    password: []const u8,
    options: HashOptions,
    out: []u8,
) Error![]const u8 {
    const allocator = options.allocator orelse return Error.AllocatorRequired;
    switch (options.encoding) {
        .phc => return PhcFormatHasher.create(
            allocator,
            password,
            options.kdf_params,
            options.mode,
            out,
        ),
        .crypt => return Error.InvalidEncoding,
    }
}

/// Options for hash verification.
///
/// Allocator is required for argon2.
pub const VerifyOptions = struct {
    allocator: ?*mem.Allocator,
};

/// Verify that a previously computed hash is valid for a given password.
pub fn strVerify(
    str: []const u8,
    password: []const u8,
    options: VerifyOptions,
) Error!void {
    const allocator = options.allocator orelse return Error.AllocatorRequired;
    return PhcFormatHasher.verify(allocator, str, password);
}

test "argon2d" {
    const password = [_]u8{0x01} ** 32;
    const salt = [_]u8{0x02} ** 16;
    const secret = [_]u8{0x03} ** 8;
    const ad = [_]u8{0x04} ** 12;

    var dk: [32]u8 = undefined;
    try kdf(
        std.testing.allocator,
        &dk,
        &password,
        &salt,
        .{ .t = 3, .m = 32, .p = 4, .secret = &secret, .ad = &ad },
        .argon2d,
        null,
    );

    const want = [_]u8{
        0x51, 0x2b, 0x39, 0x1b, 0x6f, 0x11, 0x62, 0x97,
        0x53, 0x71, 0xd3, 0x09, 0x19, 0x73, 0x42, 0x94,
        0xf8, 0x68, 0xe3, 0xbe, 0x39, 0x84, 0xf3, 0xc1,
        0xa1, 0x3a, 0x4d, 0xb9, 0xfa, 0xbe, 0x4a, 0xcb,
    };
    try std.testing.expectEqualSlices(u8, &dk, &want);
}

test "argon2i" {
    const password = [_]u8{0x01} ** 32;
    const salt = [_]u8{0x02} ** 16;
    const secret = [_]u8{0x03} ** 8;
    const ad = [_]u8{0x04} ** 12;

    var dk: [32]u8 = undefined;
    try kdf(
        std.testing.allocator,
        &dk,
        &password,
        &salt,
        .{ .t = 3, .m = 32, .p = 4, .secret = &secret, .ad = &ad },
        .argon2i,
        null,
    );

    const want = [_]u8{
        0xc8, 0x14, 0xd9, 0xd1, 0xdc, 0x7f, 0x37, 0xaa,
        0x13, 0xf0, 0xd7, 0x7f, 0x24, 0x94, 0xbd, 0xa1,
        0xc8, 0xde, 0x6b, 0x01, 0x6d, 0xd3, 0x88, 0xd2,
        0x99, 0x52, 0xa4, 0xc4, 0x67, 0x2b, 0x6c, 0xe8,
    };
    try std.testing.expectEqualSlices(u8, &dk, &want);
}

test "argon2id" {
    const password = [_]u8{0x01} ** 32;
    const salt = [_]u8{0x02} ** 16;
    const secret = [_]u8{0x03} ** 8;
    const ad = [_]u8{0x04} ** 12;

    var dk: [32]u8 = undefined;
    try kdf(
        std.testing.allocator,
        &dk,
        &password,
        &salt,
        .{ .t = 3, .m = 32, .p = 4, .secret = &secret, .ad = &ad },
        .argon2id,
        null,
    );

    const want = [_]u8{
        0x0d, 0x64, 0x0d, 0xf5, 0x8d, 0x78, 0x76, 0x6c,
        0x08, 0xc0, 0x37, 0xa3, 0x4a, 0x8b, 0x53, 0xc9,
        0xd0, 0x1e, 0xf0, 0x45, 0x2d, 0x75, 0xb6, 0x5e,
        0xb5, 0x25, 0x20, 0xe9, 0x6b, 0x01, 0xe6, 0x59,
    };
    try std.testing.expectEqualSlices(u8, &dk, &want);
}

test "kdf" {
    const password = "password";
    const salt = "somesalt";

    const TestVector = struct {
        mode: Mode,
        time: u32,
        memory: u32,
        threads: u8,
        hash: []const u8,
    };
    const test_vectors = [_]TestVector{
        .{
            .mode = .argon2i,
            .time = 1,
            .memory = 64,
            .threads = 1,
            .hash = "b9c401d1844a67d50eae3967dc28870b22e508092e861a37",
        },
        .{
            .mode = .argon2d,
            .time = 1,
            .memory = 64,
            .threads = 1,
            .hash = "8727405fd07c32c78d64f547f24150d3f2e703a89f981a19",
        },
        .{
            .mode = .argon2id,
            .time = 1,
            .memory = 64,
            .threads = 1,
            .hash = "655ad15eac652dc59f7170a7332bf49b8469be1fdb9c28bb",
        },
        .{
            .mode = .argon2i,
            .time = 2,
            .memory = 64,
            .threads = 1,
            .hash = "8cf3d8f76a6617afe35fac48eb0b7433a9a670ca4a07ed64",
        },
        .{
            .mode = .argon2d,
            .time = 2,
            .memory = 64,
            .threads = 1,
            .hash = "3be9ec79a69b75d3752acb59a1fbb8b295a46529c48fbb75",
        },
        .{
            .mode = .argon2id,
            .time = 2,
            .memory = 64,
            .threads = 1,
            .hash = "068d62b26455936aa6ebe60060b0a65870dbfa3ddf8d41f7",
        },
        .{
            .mode = .argon2i,
            .time = 2,
            .memory = 64,
            .threads = 2,
            .hash = "2089f3e78a799720f80af806553128f29b132cafe40d059f",
        },
        .{
            .mode = .argon2d,
            .time = 2,
            .memory = 64,
            .threads = 2,
            .hash = "68e2462c98b8bc6bb60ec68db418ae2c9ed24fc6748a40e9",
        },
        .{
            .mode = .argon2id,
            .time = 2,
            .memory = 64,
            .threads = 2,
            .hash = "350ac37222f436ccb5c0972f1ebd3bf6b958bf2071841362",
        },
        .{
            .mode = .argon2i,
            .time = 3,
            .memory = 256,
            .threads = 2,
            .hash = "f5bbf5d4c3836af13193053155b73ec7476a6a2eb93fd5e6",
        },
        .{
            .mode = .argon2d,
            .time = 3,
            .memory = 256,
            .threads = 2,
            .hash = "f4f0669218eaf3641f39cc97efb915721102f4b128211ef2",
        },
        .{
            .mode = .argon2id,
            .time = 3,
            .memory = 256,
            .threads = 2,
            .hash = "4668d30ac4187e6878eedeacf0fd83c5a0a30db2cc16ef0b",
        },
        .{
            .mode = .argon2i,
            .time = 4,
            .memory = 4096,
            .threads = 4,
            .hash = "a11f7b7f3f93f02ad4bddb59ab62d121e278369288a0d0e7",
        },
        .{
            .mode = .argon2d,
            .time = 4,
            .memory = 4096,
            .threads = 4,
            .hash = "935598181aa8dc2b720914aa6435ac8d3e3a4210c5b0fb2d",
        },
        .{
            .mode = .argon2id,
            .time = 4,
            .memory = 4096,
            .threads = 4,
            .hash = "145db9733a9f4ee43edf33c509be96b934d505a4efb33c5a",
        },
        .{
            .mode = .argon2i,
            .time = 4,
            .memory = 1024,
            .threads = 8,
            .hash = "0cdd3956aa35e6b475a7b0c63488822f774f15b43f6e6e17",
        },
        .{
            .mode = .argon2d,
            .time = 4,
            .memory = 1024,
            .threads = 8,
            .hash = "83604fc2ad0589b9d055578f4d3cc55bc616df3578a896e9",
        },
        .{
            .mode = .argon2id,
            .time = 4,
            .memory = 1024,
            .threads = 8,
            .hash = "8dafa8e004f8ea96bf7c0f93eecf67a6047476143d15577f",
        },
        .{
            .mode = .argon2i,
            .time = 2,
            .memory = 64,
            .threads = 3,
            .hash = "5cab452fe6b8479c8661def8cd703b611a3905a6d5477fe6",
        },
        .{
            .mode = .argon2d,
            .time = 2,
            .memory = 64,
            .threads = 3,
            .hash = "22474a423bda2ccd36ec9afd5119e5c8949798cadf659f51",
        },
        .{
            .mode = .argon2id,
            .time = 2,
            .memory = 64,
            .threads = 3,
            .hash = "4a15b31aec7c2590b87d1f520be7d96f56658172deaa3079",
        },
        .{
            .mode = .argon2i,
            .time = 3,
            .memory = 1024,
            .threads = 6,
            .hash = "d236b29c2b2a09babee842b0dec6aa1e83ccbdea8023dced",
        },
        .{
            .mode = .argon2d,
            .time = 3,
            .memory = 1024,
            .threads = 6,
            .hash = "a3351b0319a53229152023d9206902f4ef59661cdca89481",
        },
        .{
            .mode = .argon2id,
            .time = 3,
            .memory = 1024,
            .threads = 6,
            .hash = "1640b932f4b60e272f5d2207b9a9c626ffa1bd88d2349016",
        },
    };
    inline for (test_vectors) |v| {
        var want: [24]u8 = undefined;
        _ = try std.fmt.hexToBytes(&want, v.hash);

        var dk: [24]u8 = undefined;
        try kdf(
            std.testing.allocator,
            &dk,
            password,
            salt,
            .{ .t = v.time, .m = v.memory, .p = v.threads },
            v.mode,
            null,
        );

        try std.testing.expectEqualSlices(u8, &dk, &want);
    }
}

test "kdf hasher" {
    const password = "testpass";
    const salt = "saltsalt";

    var dk: [13]u8 = undefined;
    try kdf(
        std.testing.allocator,
        &dk,
        password,
        salt,
        .{ .t = 3, .m = 32, .p = 4 },
        .argon2id,
        blake2.Blake2b(13 * 8),
    );

    const hash = "a5fe3f0b0fcb4b8b705d2cb908";
    var want: [hash.len / 2]u8 = undefined;
    _ = try std.fmt.hexToBytes(&want, hash);

    try std.testing.expectEqualSlices(u8, &dk, &want);
}

test "phc format hasher" {
    const password = "testpass";
    const allocator = std.testing.allocator;

    var buf: [128]u8 = undefined;
    const hash = try PhcFormatHasher.create(
        allocator,
        password,
        .{ .t = 3, .m = 32, .p = 4 },
        .argon2id,
        &buf,
    );
    try PhcFormatHasher.verify(allocator, hash, password);
}

test "password hash and password verify" {
    const password = "testpass";
    const allocator = std.testing.allocator;

    var buf: [128]u8 = undefined;
    const hash = try strHash(
        password,
        .{
            .allocator = allocator,
            .kdf_params = .{ .t = 3, .m = 32, .p = 4 },
            .mode = .argon2id,
            .encoding = .phc,
        },
        &buf,
    );
    try strVerify(hash, password, .{ .allocator = allocator });
}
