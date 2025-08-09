// Betanet v1.0 – C# reference-ish server (first cut) (Hacked together on a friday night by Netcat)
// .NET 8 + Kestrel on 443 (HTTP/1.1/2/3). This hosts a normal-looking site,
// plus a hidden bootstrap endpoint that switches into an encrypted inner stream.
// SCION/mixnet/mesh/etc. are out of scope for this file and can be layered on later.
// For a Free internet - Fuck the gov.

using System.Buffers;
using System.Security.Cryptography;
using System.Text;
using Microsoft.AspNetCore.Server.Kestrel.Core;
using Chaos.NaCl;

var builder = WebApplication.CreateBuilder(args);

// Keep Kestrel quiet and speak every HTTP flavor on :443.
builder.WebHost.ConfigureKestrel(k =>
{
    k.AddServerHeader = false;
    k.ConfigureEndpointDefaults(e => { e.Protocols = HttpProtocols.Http1AndHttp2AndHttp3; });
});

builder.Services.AddRouting();
builder.Services.AddDirectoryBrowser();

var app = builder.Build();

// The public face: Boring ass test page.
app.MapGet("/", async ctx =>
{
    ctx.Response.ContentType = "text/html; charset=utf-8";

    // Publish the current ticket public key in Base64URL (no padding).
    var ticketPubB64Url = Convert.ToBase64String(BetaTicket.ServerKeyPair.PublicKey)
        .TrimEnd('=').Replace('+', '-').Replace('/', '_');

    await ctx.Response.WriteAsync($@"<!doctype html>
<html><head><meta charset=""utf-8""><title>Decoy</title>
<meta name=""betanet-ticket-pub"" content=""{ticketPubB64Url}"">
<style>body{{font-family:system-ui,sans-serif;margin:3rem;}}</style>
</head>
<body>
<h1>Welcome</h1>
<p>This is a perfectly ordinary site.</p>
<small>betanet ticketPub (Base64URL): <code>{ticketPubB64Url}</code></small>
</body></html>");
});

// Hidden handshake. Client proves it knows the ticket and we upgrade to a raw stream.
// The client is expected to send three headers (all Base64URL-encoded 32-byte values):
//   x-px-epub  -> client's ephemeral X25519 public key
//   x-px-nonce -> random 32B
//   x-px-ticket-> HKDF(X25519(epub, serverPriv), info="betanet-ticket|YYYYMMDDHH", salt=nonce, L=32)
app.Map("/bootstrap", async ctx =>
{
    if (!BetaTicket.TryParseHeaders(ctx.Request, out var th) || !BetaTicket.Validate(th))
    {
        // If this isn't a legit bootstrap, just act like a normal site.
        ctx.Response.Redirect("/");
        return;
    }

    // We want a raw byte stream, not WebSockets framing.
    var upgradeFeature = ctx.Features.Get<Microsoft.AspNetCore.Http.Features.IHttpUpgradeFeature>();
    if (upgradeFeature is null || !upgradeFeature.IsUpgradableRequest)
    {
        ctx.Response.StatusCode = 426;
        ctx.Response.Headers["Upgrade"] = "h2c";
        await ctx.Response.WriteAsync("upgrade required");
        return;
    }

    using var stream = await upgradeFeature.UpgradeAsync();

    // Minimal inner handshake + encrypted framing starts here.
    var inner = new HtxInner(stream);
    await inner.HandshakeNoiseXKAsync();
    await inner.RunAsync();
});

app.Run();


// ---------------------------- Ticket logic ----------------------------
// We use a static X25519 keypair to mint/verify hour-rotating tickets.
// The public half is exposed on "/", the private half stays here.
static class BetaTicket
{
    public static readonly (byte[] PublicKey, byte[] PrivateKey) ServerKeyPair = CreateX25519KeyPair();

    public sealed record TicketHeaders(byte[] ClientEphPub, byte[] Nonce, byte[] Ticket);

    // Grab and sanity-check the three headers we expect for bootstrap.
    public static bool TryParseHeaders(HttpRequest req, out TicketHeaders headers)
    {
        headers = null!;
        if (!req.Headers.TryGetValue("x-px-epub", out var e) || !TryB64Url(e.ToString(), 32, out var epub)) return false;
        if (!req.Headers.TryGetValue("x-px-nonce", out var n) || !TryB64Url(n.ToString(), 32, out var nonce)) return false;
        if (!req.Headers.TryGetValue("x-px-ticket", out var t) || !TryB64Url(t.ToString(), 32, out var ticket)) return false;
        headers = new TicketHeaders(epub, nonce, ticket);
        return true;
    }

    // Recompute the expected ticket for the current (and previous) UTC hour.
    public static bool Validate(TicketHeaders th)
    {
        var ss = X25519ScalarMult(th.ClientEphPub, ServerKeyPair.PrivateKey);
        var expectedNow = DeriveTicket(ss, th.Nonce, DateTime.UtcNow);
        var expectedPrev = DeriveTicket(ss, th.Nonce, DateTime.UtcNow.AddHours(-1));

        return CryptographicOperations.FixedTimeEquals(expectedNow, th.Ticket)
            || CryptographicOperations.FixedTimeEquals(expectedPrev, th.Ticket);
    }

    private static byte[] DeriveTicket(byte[] sharedSecret, byte[] nonce, DateTime utc)
    {
        var info = Encoding.ASCII.GetBytes($"betanet-ticket|{utc:yyyyMMddHH}");
        return HkdfSha256(sharedSecret, nonce, info, 32);
    }

    // Base64URL decode helper that enforces a specific size.
    private static bool TryB64Url(string b64url, int size, out byte[] bytes)
    {
        bytes = Array.Empty<byte>();
        try
        {
            string s = b64url.Replace('-', '+').Replace('_', '/');
            switch (s.Length % 4) { case 2: s += "=="; break; case 3: s += "="; break; }
            bytes = Convert.FromBase64String(s);
            return bytes.Length == size;
        }
        catch { return false; }
    }

    // X25519 helpers using Chaos.NaCl's short-form API.
    private static (byte[] pub, byte[] priv) CreateX25519KeyPair()
    {
        var priv = new byte[32];
        RandomNumberGenerator.Fill(priv);

        var pub = new byte[32];
        MontgomeryCurve25519.GetPublicKey(pub, priv);
        return (pub, priv);
    }

    private static byte[] X25519ScalarMult(byte[] otherPub, byte[] priv)
    {
        var ss = new byte[32];
        MontgomeryCurve25519.KeyExchange(ss, priv, otherPub);
        return ss;
    }

    // Tiny HKDF-SHA256 (extract+expand).
    private static byte[] HkdfSha256(byte[] ikm, byte[] salt, byte[] info, int len)
    {
        using var hmac = new HMACSHA256(salt);
        var prk = hmac.ComputeHash(ikm);
        var okm = new byte[len];
        var t = Array.Empty<byte>();
        int copied = 0; byte counter = 1;

        while (copied < len)
        {
            hmac.Key = prk; hmac.Initialize();
            hmac.TransformBlock(t, 0, t.Length, null, 0);
            hmac.TransformBlock(info, 0, info.Length, null, 0);
            hmac.TransformFinalBlock(new[] { counter }, 0, 1);

            t = hmac.Hash!;
            var take = Math.Min(t.Length, len - copied);
            Array.Copy(t, 0, okm, copied, take);
            copied += take; counter++;
        }
        return okm;
    }
}


// ---------------------------- Inner channel ----------------------------
// After /bootstrap upgrades, we run a tiny handshake to agree on a key,
// then exchange encrypted frames. This is intentionally small so you can
// swap it out for a real Noise/TLS-EKM derivation later without pain.
sealed class HtxInner
{
    private readonly Stream _io;
    private byte[] _k = Array.Empty<byte>(); // inner key
    private ulong _sendCtr;                  // 96-bit LE nonce (we use low 64 bits)
    private ulong _recvCtr;

    public HtxInner(Stream io) => _io = io;

    // Minimal “XK-ish” exchange: client sends its 32B eph pub, we reply with ours,
    // both sides do X25519 and HKDF a key. No identities, no rekey—keep expectations low.
    public async Task HandshakeNoiseXKAsync()
    {
        byte[] eC = await ReadExactlyAsync(32);

        var eSpriv = new byte[32]; RandomNumberGenerator.Fill(eSpriv);
        var eSpub = new byte[32]; MontgomeryCurve25519.GetPublicKey(eSpub, eSpriv);

        var ss = new byte[32]; MontgomeryCurve25519.KeyExchange(ss, eSpriv, eC);

        await _io.WriteAsync(eSpub);
        await _io.FlushAsync();

        _k = HkdfSha256(ss, Array.Empty<byte>(), Encoding.ASCII.GetBytes("htx-noise"), 32);
        _sendCtr = 0; _recvCtr = 0;
    }

    // Keep the line alive with occasional PING and idle padding.
    // For now, this just echoes STREAM data back on an even stream id.
    public async Task RunAsync()
    {
        _ = Task.Run(async () =>
        {
            var rnd = Random.Shared;
            while (true)
            {
                await Task.Delay(TimeSpan.FromSeconds(15 + rnd.Next(-3, 4)));
                await SendPingAsync();
            }
        });

        _ = Task.Run(async () =>
        {
            var rnd = Random.Shared;
            while (true)
            {
                await Task.Delay(TimeSpan.FromMilliseconds(512 + rnd.Next(-128, 129)));
                await SendFrameAsync(FrameType.Stream, 0UL, new byte[1024]); // 1 KiB padding
            }
        });

        while (true)
        {
            var frame = await ReadFrameAsync();
            if (frame.Type == FrameType.Ping) continue;
            if (frame.Type == FrameType.Close) break;

            if (frame.Type == FrameType.Stream)
            {
                var outId = (frame.StreamId % 2 == 0) ? frame.StreamId : frame.StreamId + 1;
                await SendFrameAsync(FrameType.Stream, outId, frame.Payload);
            }
        }
    }

    enum FrameType : byte { Stream = 0, Ping = 1, Close = 2 }
    readonly record struct Frame(FrameType Type, ulong StreamId, byte[] Payload);

    private async Task SendPingAsync() => await SendFrameAsync(FrameType.Ping, 0, Array.Empty<byte>());

    // Frame layout:
    //   uint24 length (ciphertext, not counting the tag)
    //   uint8  type
    //   varint stream_id (only if type==STREAM)
    //   ciphertext || tag(16)
    private async Task SendFrameAsync(FrameType type, ulong streamId, byte[] payload)
    {
        // AEAD( key, nonce = 96-bit LE counter )
        var (ct, tag) = AeadEncrypt(_k, _sendCtr, payload);
        _sendCtr++;

        var buf = new ArrayBufferWriter<byte>(5 + 10 + ct.Length + 16);
        uint len = (uint)ct.Length;

        var s3 = buf.GetSpan(3); s3[0] = (byte)(len >> 16); s3[1] = (byte)(len >> 8); s3[2] = (byte)len; buf.Advance(3);
        buf.GetSpan(1)[0] = (byte)type; buf.Advance(1);
        if (type == FrameType.Stream) WriteVarInt(ref buf, streamId);
        buf.Write(ct); buf.Write(tag);

        await _io.WriteAsync(buf.WrittenSpan.ToArray());
        await _io.FlushAsync();
    }

    private async Task<Frame> ReadFrameAsync()
    {
        var lenBuf = await ReadExactlyAsync(3);
        uint len = (uint)(lenBuf[0] << 16 | lenBuf[1] << 8 | lenBuf[2]);

        var type = (FrameType)(await ReadExactlyAsync(1))[0];
        ulong sid = 0;
        if (type == FrameType.Stream) sid = await ReadVarIntAsync();

        var ct = await ReadExactlyAsync((int)len);
        var tag = await ReadExactlyAsync(16);

        var pt = AeadDecrypt(_k, _recvCtr++, ct, tag);
        return new Frame(type, sid, pt);
    }

    // QUIC varint encoding/decoding (enough for stream IDs).
    private static void WriteVarInt(ref ArrayBufferWriter<byte> buf, ulong value)
    {
        if (value <= 63) { buf.GetSpan(1)[0] = (byte)value; buf.Advance(1); return; }
        if (value <= 16383) { var s = buf.GetSpan(2); s[0] = (byte)(0x40 | (value >> 8)); s[1] = (byte)value; buf.Advance(2); return; }
        if (value <= 1073741823) { var s = buf.GetSpan(4); s[0] = (byte)(0x80 | (value >> 24)); s[1] = (byte)(value >> 16); s[2] = (byte)(value >> 8); s[3] = (byte)value; buf.Advance(4); return; }
        { var s = buf.GetSpan(8); s[0] = (byte)(0xC0 | (value >> 56)); s[1] = (byte)(value >> 48); s[2] = (byte)(value >> 40); s[3] = (byte)(value >> 32); s[4] = (byte)(value >> 24); s[5] = (byte)(value >> 16); s[6] = (byte)(value >> 8); s[7] = (byte)value; buf.Advance(8); }
    }

    private async Task<ulong> ReadVarIntAsync()
    {
        int b0 = (await ReadExactlyAsync(1))[0];
        int prefix = b0 >> 6;
        int len = 1 << prefix; // 1,2,4,8
        byte[] rest = len == 1 ? Array.Empty<byte>() : await ReadExactlyAsync(len - 1);
        ulong v = (ulong)(b0 & 0x3F);
        for (int i = 0; i < rest.Length; i++) v = (v << 8) | rest[i];
        return v;
    }

    // Read exactly N bytes from the upgraded stream (no surprises).
    private async Task<byte[]> ReadExactlyAsync(int n)
    {
        var buf = new byte[n];
        int off = 0;
        while (off < n)
        {
            int r = await _io.ReadAsync(buf.AsMemory(off, n - off));
            if (r == 0) throw new EndOfStreamException();
            off += r;
        }
        return buf;
    }

    // AEAD helpers using the BCL ChaCha20-Poly1305 (so we avoid third-party ambiguity).
    private static (byte[] ct, byte[] tag) AeadEncrypt(byte[] key, ulong leCtr, byte[] pt)
    {
        var nonce = new byte[12];
        BitConverter.TryWriteBytes(nonce.AsSpan(0, 8), leCtr);

        var ct = new byte[pt.Length];
        var tag = new byte[16];
        using var aead = new System.Security.Cryptography.ChaCha20Poly1305(key);
        aead.Encrypt(nonce, pt, ct, tag, associatedData: null);
        return (ct, tag);
    }

    private static byte[] AeadDecrypt(byte[] key, ulong leCtr, byte[] ct, byte[] tag)
    {
        var nonce = new byte[12];
        BitConverter.TryWriteBytes(nonce.AsSpan(0, 8), leCtr);

        var pt = new byte[ct.Length];
        using var aead = new System.Security.Cryptography.ChaCha20Poly1305(key);
        aead.Decrypt(nonce, ct, tag, pt, associatedData: null);
        return pt;
    }

    // Local HKDF so we don’t reach across to BetaTicket’s internals.
    private static byte[] HkdfSha256(byte[] ikm, byte[] salt, byte[] info, int len)
    {
        using var hmac = new HMACSHA256(salt);
        var prk = hmac.ComputeHash(ikm);
        var okm = new byte[len];
        var t = Array.Empty<byte>();
        int copied = 0; byte counter = 1;

        while (copied < len)
        {
            hmac.Key = prk; hmac.Initialize();
            hmac.TransformBlock(t, 0, t.Length, null, 0);
            hmac.TransformBlock(info, 0, info.Length, null, 0);
            hmac.TransformFinalBlock(new[] { counter }, 0, 1);

            t = hmac.Hash!;
            var take = Math.Min(t.Length, len - copied);
            Array.Copy(t, 0, okm, copied, take);
            copied += take; counter++;
        }
        return okm;
    }
}
