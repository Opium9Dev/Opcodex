using System.IO;
using System.Buffers.Binary;

namespace Opcodex.Pyc;

public static class PycMagic
{

    static readonly (int lo, int hi, int minor)[] Ranges =
    {
        (3400, 3419, 8),  (3420, 3429, 9),  (3430, 3449, 10), (3450, 3499, 11),
        (3500, 3549, 12), (3550, 3599, 13), (3600, 3649, 14), (3650, 3699, 15),
    };

    public static bool TryGetVersion(int magic, out int major, out int minor, out string error)
    {
        major = 3; minor = 0; error = null;
        foreach (var (lo, hi, m) in Ranges)
            if (magic >= lo && magic <= hi) { minor = m; return true; }
        if (magic < 3400)
            error = $"Unsupported pyc (magic number {magic}): Python older than 3.8 is not supported.";
        else
            error = $"Unsupported pyc (magic number {magic}): Python newer than 3.15 is not supported.";
        return false;
    }
}

public sealed class PycFile
{
    public string Path = "";
    public byte[] Raw = Array.Empty<byte>();

    public int MagicNumber;
    public byte[] MagicBytes = new byte[4];
    public int Major = 3, Minor;
    public string VersionText => $"{Major}.{Minor}";

    public uint Flags;
    public bool HashBased => (Flags & 1) != 0;
    public bool CheckSource => (Flags & 2) != 0;
    public uint Timestamp, SourceSize;
    public byte[] SourceHash = Array.Empty<byte>();

    public const int HeaderSize = 16;
    public int TrailingBytes;

    public PyCode Root;
    public List<PyCode> AllCode = new();
    public OpcodeTable Opcodes;

    public static PycFile Load(string path) => Parse(File.ReadAllBytes(path), path);

    public static PycFile Parse(byte[] data, string path, Action<double> progress = null, CancellationToken ct = default)
    {
        if (data.Length < HeaderSize)
            throw new PycFormatException("File too small to be a .pyc (the header is 16 bytes).");
        if (data[2] != 0x0D || data[3] != 0x0A)
            throw new PycFormatException("Not a .pyc file: bytes 2-3 of the magic number are not CR LF.");

        int magic = data[0] | (data[1] << 8);
        if (!PycMagic.TryGetVersion(magic, out int major, out int minor, out string err))
            throw new PycFormatException(err);

        var f = new PycFile
        {
            Path = path, Raw = data, MagicNumber = magic, Major = major, Minor = minor,
            MagicBytes = data[0..4],
            Flags = BinaryPrimitives.ReadUInt32LittleEndian(data.AsSpan(4, 4)),
            Opcodes = OpcodeTable.For(major, minor),
        };
        if (f.HashBased) f.SourceHash = data[8..16];
        else
        {
            f.Timestamp = BinaryPrimitives.ReadUInt32LittleEndian(data.AsSpan(8, 4));
            f.SourceSize = BinaryPrimitives.ReadUInt32LittleEndian(data.AsSpan(12, 4));
        }

        var reader = new MarshalReader(data, HeaderSize, major, minor) { Progress = progress, Cancel = ct };
        var root = reader.ReadObject();
        if (root is not PyCode code)
            throw new PycFormatException($"The marshalled root object is not a code object (got {root?.TypeName ?? "NULL"}).");
        f.Root = code;
        f.AllCode = reader.AllCode;
        f.TrailingBytes = data.Length - reader.Position;
        return f;
    }
}
