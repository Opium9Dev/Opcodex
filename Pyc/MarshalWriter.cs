using System.Numerics;
using System.Text;

namespace Opcodex.Pyc;

public sealed class MarshalWriter
{
    readonly List<byte> _b = new();
    readonly int _minor;

    MarshalWriter(int minor) { _minor = minor; }

    public static byte[] Build(PycFile f, bool clearCheckSource = false)
    {
        var w = new MarshalWriter(f.Minor);
        byte[] header = f.Raw[0..PycFile.HeaderSize];
        if (clearCheckSource && f.HashBased)
        {
            uint flags = f.Flags & ~2u;
            byte[] fb = BitConverter.GetBytes(flags);
            Buffer.BlockCopy(fb, 0, header, 4, 4);
        }
        w._b.AddRange(header);
        w.Write(f.Root);
        return w._b.ToArray();
    }

    void U8(int v) => _b.Add((byte)v);
    void U16(int v) { _b.Add((byte)v); _b.Add((byte)(v >> 8)); }
    void I32(int v) => _b.AddRange(BitConverter.GetBytes(v));
    void F64(double d) => _b.AddRange(BitConverter.GetBytes(d));

    static PyTuple StrTuple(IEnumerable<string> items)
    {
        var t = new PyTuple();
        foreach (var s in items) t.Items.Add(new PyStr(s));
        return t;
    }

    void Write(PyObj o)
    {
        switch (o)
        {
            case null: U8('0'); break;
            case PyNone: U8('N'); break;
            case PyBool b: U8(b.Value ? 'T' : 'F'); break;
            case PyStopIteration: U8('S'); break;
            case PyEllipsis: U8('.'); break;
            case PyInt i: WriteInt(i.Value); break;
            case PyFloat f: U8('g'); F64(f.Value); break;
            case PyComplex c: U8('y'); F64(c.Re); F64(c.Im); break;
            case PyStr s: WriteStr(s.Value); break;
            case PyBytes by: U8('s'); I32(by.Data.Length); _b.AddRange(by.Data); break;
            case PyTuple t:
                if (t.Items.Count < 256) { U8(')'); U8(t.Items.Count); }
                else { U8('('); I32(t.Items.Count); }
                foreach (var x in t.Items) Write(x);
                break;
            case PyList l:
                U8('['); I32(l.Items.Count);
                foreach (var x in l.Items) Write(x);
                break;
            case PyDict d:
                U8('{');
                foreach (var kv in d.Items) { Write(kv.Key); Write(kv.Value); }
                U8('0');
                break;
            case PySet st:
                U8(st.Frozen ? '>' : '<'); I32(st.Items.Count);
                foreach (var x in st.Items) Write(x);
                break;
            case PySlice sl: U8(':'); Write(sl.Start); Write(sl.Stop); Write(sl.Step); break;
            case PyCode code: WriteCode(code); break;
            default: throw new PycFormatException($"Cannot marshal object of type {o.TypeName}");
        }
    }

    void WriteInt(BigInteger v)
    {
        if (v >= int.MinValue && v <= int.MaxValue) { U8('i'); I32((int)v); return; }
        var mag = BigInteger.Abs(v);
        var digits = new List<int>();
        while (!mag.IsZero) { digits.Add((int)(mag & 0x7FFF)); mag >>= 15; }
        U8('l');
        I32(v.Sign < 0 ? -digits.Count : digits.Count);
        foreach (int d in digits) U16(d);
    }

    void WriteStr(string s)
    {
        bool ascii = true;
        foreach (char c in s) if (c >= 128) { ascii = false; break; }
        if (ascii && s.Length < 256) { U8('z'); U8(s.Length); _b.AddRange(Encoding.ASCII.GetBytes(s)); }
        else if (ascii) { U8('a'); I32(s.Length); _b.AddRange(Encoding.ASCII.GetBytes(s)); }
        else { var u = Encoding.UTF8.GetBytes(s); U8('u'); I32(u.Length); _b.AddRange(u); }
    }

    void WriteCode(PyCode c)
    {
        U8('c');
        I32(c.ArgCount); I32(c.PosOnlyArgCount); I32(c.KwOnlyArgCount);
        if (_minor < 11) I32(c.NLocals);
        I32(c.StackSize); I32(c.Flags);

        Write(c.Code);
        var consts = new PyTuple();
        consts.Items.AddRange(c.Consts);
        Write(consts);
        Write(StrTuple(c.Names));

        if (_minor < 11)
        {
            Write(StrTuple(c.VarNames));
            Write(StrTuple(c.FreeVars));
            Write(StrTuple(c.CellVars));
        }
        else
        {
            Write(StrTuple(c.LocalsPlusNames ?? Array.Empty<string>()));
            Write(new PyBytes(c.LocalsPlusKinds ?? Array.Empty<byte>(), -1));
        }

        Write(new PyStr(c.Filename));
        Write(new PyStr(c.Name));
        if (_minor >= 11) Write(new PyStr(c.QualName));
        I32(c.FirstLineNo);
        Write(new PyBytes(c.LineTable, -1));
        if (_minor >= 11) Write(new PyBytes(c.ExceptionTable, -1));
    }
}
