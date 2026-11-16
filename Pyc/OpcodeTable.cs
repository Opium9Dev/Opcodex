namespace Opcodex.Pyc;

public sealed partial class OpcodeTable
{
    public int Major, Minor, HaveArgument, ExtendedArg;
    public string[] Cmp = Array.Empty<string>();
    public string[] NbOps = Array.Empty<string>();

    readonly string[] _names = new string[256];
    readonly int[] _flags = new int[256];
    readonly int[] _caches = new int[256];
    readonly Dictionary<string, int> _byName = new();

    static readonly Dictionary<int, OpcodeTable> Tables = new();

    OpcodeTable() { }

    void Add(int op, string name, int flags, int caches)
    {
        _names[op] = name;
        _flags[op] = flags;
        _caches[op] = caches;
        _byName[name] = op;
    }

    public static readonly int MinMinor = 8, MaxMinor = 15;

    public static OpcodeTable For(int major, int minor)
    {
        if (major != 3 || minor < MinMinor || minor > MaxMinor)
            throw new PycFormatException($"Python {major}.{minor} is not supported (supported: 3.{MinMinor} - 3.{MaxMinor})");
        lock (Tables)
        {
            if (!Tables.TryGetValue(minor, out var t))
            {
                t = Build(major, minor);
                Tables[minor] = t;
            }
            return t;
        }
    }

    public bool IsKnown(int op) => op >= 0 && op < 256 && _names[op] != null;
    public string Name(int op) => IsKnown(op) ? _names[op] : $"<{op}>";
    public int Flags(int op) => IsKnown(op) ? _flags[op] : 0;
    public bool Has(int op, int flag) => (Flags(op) & flag) != 0;
    public int Caches(int op) => IsKnown(op) ? _caches[op] : 0;
    public bool HasArg(int op) => IsKnown(op) ? (_flags[op] & FArg) != 0 : op >= HaveArgument;
    public bool TryGetOpcode(string name, out int op) => _byName.TryGetValue(name, out op);
    public IEnumerable<string> AllNames() => _byName.Keys;

    public static string Intrinsic1Name(int i) => i >= 0 && i < Intrinsic1.Length ? Intrinsic1[i] : null;
    public static string Intrinsic2Name(int i) => i >= 0 && i < Intrinsic2.Length ? Intrinsic2[i] : null;
}
