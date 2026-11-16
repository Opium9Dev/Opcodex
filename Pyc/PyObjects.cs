using System.Globalization;
using System.Numerics;
using System.Text;

namespace Opcodex.Pyc;

public abstract class PyObj
{
    public abstract string TypeName { get; }
    public abstract string ReprD(int depth);
    public string Repr() => ReprD(0);
    public override string ToString() => Repr();

    protected static string R(PyObj o, int depth) => o == null ? "<NULL>" : depth > 12 ? "..." : o.ReprD(depth + 1);

    public static string Trunc(string s, int max) => s.Length <= max ? s : s.Substring(0, max) + "…";

    public static string StrRepr(string s)
    {
        char q = (s.Contains('\'') && !s.Contains('"')) ? '"' : '\'';
        var sb = new StringBuilder();
        sb.Append(q);
        foreach (char c in s)
        {
            if (c == q || c == '\\') sb.Append('\\').Append(c);
            else if (c == '\n') sb.Append("\\n");
            else if (c == '\r') sb.Append("\\r");
            else if (c == '\t') sb.Append("\\t");
            else if (c < 0x20 || c == 0x7F || (c >= 0x80 && c < 0xA0)) sb.Append("\\x").Append(((int)c).ToString("x2"));
            else sb.Append(c);
        }
        sb.Append(q);
        return sb.ToString();
    }

    public static string BytesRepr(byte[] b)
    {
        bool hasS = false, hasD = false;
        foreach (byte x in b) { if (x == '\'') hasS = true; else if (x == '"') hasD = true; }
        char q = (hasS && !hasD) ? '"' : '\'';
        var sb = new StringBuilder("b");
        sb.Append(q);
        foreach (byte x in b)
        {
            if (x == q || x == '\\') sb.Append('\\').Append((char)x);
            else if (x == '\n') sb.Append("\\n");
            else if (x == '\r') sb.Append("\\r");
            else if (x == '\t') sb.Append("\\t");
            else if (x < 0x20 || x >= 0x7F) sb.Append("\\x").Append(x.ToString("x2"));
            else sb.Append((char)x);
        }
        sb.Append(q);
        return sb.ToString();
    }

    public static string FloatRepr(double d)
    {
        if (double.IsNaN(d)) return "nan";
        if (double.IsPositiveInfinity(d)) return "inf";
        if (double.IsNegativeInfinity(d)) return "-inf";
        string r = d.ToString("R", CultureInfo.InvariantCulture);
        int e = r.IndexOf('E');
        if (e >= 0)
        {
            string mant = r.Substring(0, e);
            int exp = int.Parse(r.Substring(e + 1), CultureInfo.InvariantCulture);
            if (mant.EndsWith(".0")) mant = mant.Substring(0, mant.Length - 2);
            return mant + "e" + (exp < 0 ? "-" : "+") + Math.Abs(exp).ToString("00");
        }
        if (r.IndexOf('.') < 0) r += ".0";
        return r;
    }

    static string Short(double d)
    {
        string s = FloatRepr(d);
        return s.EndsWith(".0") ? s.Substring(0, s.Length - 2) : s;
    }

    public static string ComplexRepr(double re, double im)
    {
        if (re == 0 && !double.IsNegative(re)) return Short(im) + "j";
        string i = Short(im);
        if (!i.StartsWith("-") && !i.StartsWith("+")) i = "+" + i;
        return "(" + Short(re) + i + "j)";
    }
}

public sealed class PyNone : PyObj
{
    public static readonly PyNone Instance = new();
    public override string TypeName => "NoneType";
    public override string ReprD(int depth) => "None";
}

public sealed class PyBool : PyObj
{
    public static readonly PyBool True = new(true), False = new(false);
    public readonly bool Value;
    PyBool(bool v) { Value = v; }
    public override string TypeName => "bool";
    public override string ReprD(int depth) => Value ? "True" : "False";
}

public sealed class PyEllipsis : PyObj
{
    public static readonly PyEllipsis Instance = new();
    public override string TypeName => "ellipsis";
    public override string ReprD(int depth) => "Ellipsis";
}

public sealed class PyStopIteration : PyObj
{
    public static readonly PyStopIteration Instance = new();
    public override string TypeName => "StopIteration";
    public override string ReprD(int depth) => "StopIteration";
}

public sealed class PyInt : PyObj
{
    public readonly BigInteger Value;
    public PyInt(BigInteger v) { Value = v; }
    public override string TypeName => "int";
    public override string ReprD(int depth) => Value.ToString(CultureInfo.InvariantCulture);
}

public sealed class PyFloat : PyObj
{
    public readonly double Value;
    public PyFloat(double v) { Value = v; }
    public override string TypeName => "float";
    public override string ReprD(int depth) => FloatRepr(Value);
}

public sealed class PyComplex : PyObj
{
    public readonly double Re, Im;
    public PyComplex(double re, double im) { Re = re; Im = im; }
    public override string TypeName => "complex";
    public override string ReprD(int depth) => ComplexRepr(Re, Im);
}

public sealed class PyStr : PyObj
{
    public readonly string Value;
    public PyStr(string v) { Value = v; }
    public override string TypeName => "str";
    public override string ReprD(int depth) => StrRepr(Value);
}

public sealed class PyBytes : PyObj
{
    public readonly byte[] Data;

    public readonly int FileOffset;

    public int SharedRefs;
    public PyBytes(byte[] data, int fileOffset) { Data = data; FileOffset = fileOffset; }
    public override string TypeName => "bytes";
    public override string ReprD(int depth) => BytesRepr(Data);
}

public sealed class PyTuple : PyObj
{
    public readonly List<PyObj> Items = new();
    public override string TypeName => "tuple";
    public override string ReprD(int depth)
    {
        if (Items.Count == 0) return "()";
        if (Items.Count == 1) return "(" + R(Items[0], depth) + ",)";
        return "(" + string.Join(", ", Items.Select(i => R(i, depth))) + ")";
    }
}

public sealed class PyList : PyObj
{
    public readonly List<PyObj> Items = new();
    public override string TypeName => "list";
    public override string ReprD(int depth) => "[" + string.Join(", ", Items.Select(i => R(i, depth))) + "]";
}

public sealed class PyDict : PyObj
{
    public readonly List<KeyValuePair<PyObj, PyObj>> Items = new();
    public override string TypeName => "dict";
    public override string ReprD(int depth) =>
        "{" + string.Join(", ", Items.Select(kv => R(kv.Key, depth) + ": " + R(kv.Value, depth))) + "}";
}

public sealed class PySet : PyObj
{
    public readonly bool Frozen;
    public readonly List<PyObj> Items = new();
    public PySet(bool frozen) { Frozen = frozen; }
    public override string TypeName => Frozen ? "frozenset" : "set";
    public override string ReprD(int depth)
    {
        string body = Items.Count == 0 ? "" : "{" + string.Join(", ", Items.Select(i => R(i, depth))) + "}";
        if (Frozen) return Items.Count == 0 ? "frozenset()" : "frozenset(" + body + ")";
        return Items.Count == 0 ? "set()" : body;
    }
}

public sealed class PySlice : PyObj
{
    public PyObj Start, Stop, Step;
    public override string TypeName => "slice";
    public override string ReprD(int depth) => $"slice({R(Start, depth)}, {R(Stop, depth)}, {R(Step, depth)})";
}

public sealed class PyCode : PyObj
{
    public int Major, Minor;

    public int ArgCount, PosOnlyArgCount, KwOnlyArgCount;

    public int NLocals = -1;
    public int StackSize, Flags, FirstLineNo;

    public PyBytes Code;
    public List<PyObj> Consts = new();
    public string[] Names = Array.Empty<string>();

    public string[] VarNames = Array.Empty<string>();
    public string[] FreeVars = Array.Empty<string>();
    public string[] CellVars = Array.Empty<string>();

    public string[] LocalsPlusNames;
    public byte[] LocalsPlusKinds;

    public string Filename = "", Name = "", QualName = "";

    public byte[] LineTable = Array.Empty<byte>();
    public byte[] ExceptionTable = Array.Empty<byte>();

    public PyCode Parent;
    public readonly List<PyCode> Children = new();

    public PyCode ShallowCopy() => (PyCode)MemberwiseClone();

    public override string TypeName => "code";
    public override string ReprD(int depth) => $"<code object {Name}, file {StrRepr(Filename)}, line {FirstLineNo}>";

    public bool IsModule => Name == "<module>";

    public bool IsClassBody => !IsModule && (Flags & 0x3) == 0;

    static readonly (int bit, string name)[] FlagNames =
    {
        (0x1, "OPTIMIZED"), (0x2, "NEWLOCALS"), (0x4, "VARARGS"), (0x8, "VARKEYWORDS"), (0x10, "NESTED"),
        (0x20, "GENERATOR"), (0x40, "NOFREE"), (0x80, "COROUTINE"), (0x100, "ITERABLE_COROUTINE"),
        (0x200, "ASYNC_GENERATOR"), (0x4000000, "HAS_DOCSTRING"), (0x8000000, "METHOD"),
    };

    public string FlagsText()
    {
        var parts = new List<string>();
        foreach (var (bit, name) in FlagNames) if ((Flags & bit) != 0) parts.Add(name);
        return parts.Count == 0 ? "" : string.Join("|", parts);
    }
}
