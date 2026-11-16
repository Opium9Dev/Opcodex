using System.Buffers.Binary;
using System.Globalization;
using System.Numerics;
using System.Text;

namespace Opcodex.Pyc;

public sealed class PycFormatException : Exception
{
    public PycFormatException(string message) : base(message) { }
}

public sealed class MarshalReader
{
    readonly byte[] _d;
    int _p;
    readonly int _major, _minor;
    readonly List<PyObj> _refs = new();
    int _depth;

    public List<PyCode> AllCode { get; } = new();
    public int Position => _p;

    public Action<double> Progress;

    public CancellationToken Cancel;
    int _objCount;

    public MarshalReader(byte[] data, int start, int major, int minor)
    {
        _d = data; _p = start; _major = major; _minor = minor;
    }

    void Need(int n)
    {
        if (n < 0 || (long)_p + n > _d.Length)
            throw new PycFormatException($"Unexpected end of data at offset 0x{_p:X} (needed {n} byte(s))");
    }
    byte U8() { Need(1); return _d[_p++]; }
    ushort U16() { Need(2); ushort v = BinaryPrimitives.ReadUInt16LittleEndian(_d.AsSpan(_p, 2)); _p += 2; return v; }
    int I32() { Need(4); int v = BinaryPrimitives.ReadInt32LittleEndian(_d.AsSpan(_p, 4)); _p += 4; return v; }
    long I64() { Need(8); long v = BinaryPrimitives.ReadInt64LittleEndian(_d.AsSpan(_p, 8)); _p += 8; return v; }
    double F64() => BitConverter.Int64BitsToDouble(I64());
    byte[] Bytes(int n) { Need(n); var b = new byte[n]; Buffer.BlockCopy(_d, _p, b, 0, n); _p += n; return b; }
    string Utf8(int n) { Need(n); string s = Encoding.UTF8.GetString(_d, _p, n); _p += n; return s; }
    string Ascii(int n) { Need(n); string s = Encoding.Latin1.GetString(_d, _p, n); _p += n; return s; }

    static double ParseFloat(string s)
    {
        switch (s.Trim().ToLowerInvariant())
        {
            case "inf": case "+inf": return double.PositiveInfinity;
            case "-inf": return double.NegativeInfinity;
            case "nan": case "-nan": case "+nan": return double.NaN;
        }
        return double.Parse(s, NumberStyles.Float, CultureInfo.InvariantCulture);
    }

    int Reserve(bool flag)
    {
        if (!flag) return -1;
        _refs.Add(null);
        return _refs.Count - 1;
    }
    void Fill(int idx, PyObj o) { if (idx >= 0) _refs[idx] = o; }
    PyObj Reg(PyObj o, bool flag) { if (flag) _refs.Add(o); return o; }

    public PyObj ReadObject()
    {
        if (++_depth > 3000) throw new PycFormatException("Marshal data nested too deeply");
        if ((++_objCount & 0x3FF) == 0)
        {
            Cancel.ThrowIfCancellationRequested();
            Progress?.Invoke(_d.Length == 0 ? 1.0 : (double)_p / _d.Length);
        }
        try { return ReadInner(); }
        finally { _depth--; }
    }

    int Count(int n)
    {

        if (n < 0 || n > _d.Length) throw new PycFormatException($"Invalid element count {n} at offset 0x{_p:X}");
        return n;
    }

    PyObj ReadInner()
    {
        int pos0 = _p;
        byte b = U8();
        bool flag = (b & 0x80) != 0;
        char type = (char)(b & 0x7F);

        switch (type)
        {
            case '0': return null;
            case 'N': return PyNone.Instance;
            case 'F': return PyBool.False;
            case 'T': return PyBool.True;
            case 'S': return PyStopIteration.Instance;
            case '.': return PyEllipsis.Instance;

            case 'i': return Reg(new PyInt(I32()), flag);
            case 'I': return Reg(new PyInt(I64()), flag);
            case 'l':
            {
                int n = I32();
                int size = Count(Math.Abs(n));
                Need(size * 2);
                BigInteger v = BigInteger.Zero;
                for (int i = 0; i < size; i++) v |= (BigInteger)U16() << (15 * i);
                return Reg(new PyInt(n < 0 ? -v : v), flag);
            }
            case 'f': { int n = U8(); return Reg(new PyFloat(ParseFloat(Ascii(n))), flag); }
            case 'g': return Reg(new PyFloat(F64()), flag);
            case 'x':
            {
                int n1 = U8(); double re = ParseFloat(Ascii(n1));
                int n2 = U8(); double im = ParseFloat(Ascii(n2));
                return Reg(new PyComplex(re, im), flag);
            }
            case 'y': { double re = F64(); double im = F64(); return Reg(new PyComplex(re, im), flag); }

            case 's':
            {
                int n = I32();
                Need(n);
                int off = _p;
                return Reg(new PyBytes(Bytes(n), off), flag);
            }
            case 't': case 'u': case 'A': case 'a':
            {
                int n = I32();
                string s = (type == 'a' || type == 'A') ? Ascii(n) : Utf8(n);
                return Reg(new PyStr(s), flag);
            }
            case 'z': case 'Z': { int n = U8(); return Reg(new PyStr(Ascii(n)), flag); }

            case '(': case ')':
            {
                int n = type == ')' ? U8() : I32();
                var t = new PyTuple();
                Fill(Reserve(flag), t);
                int cnt = Count(n);
                for (int i = 0; i < cnt; i++) t.Items.Add(ReadObject());
                return t;
            }
            case '[':
            {
                int n = Count(I32());
                var l = new PyList();
                Fill(Reserve(flag), l);
                for (int i = 0; i < n; i++) l.Items.Add(ReadObject());
                return l;
            }
            case '{':
            {
                var dict = new PyDict();
                Fill(Reserve(flag), dict);
                while (true)
                {
                    var k = ReadObject();
                    if (k == null) break;
                    var v = ReadObject();
                    if (v == null) break;
                    dict.Items.Add(new KeyValuePair<PyObj, PyObj>(k, v));
                }
                return dict;
            }
            case '<': case '>':
            {
                int n = Count(I32());
                var s = new PySet(type == '>');
                Fill(Reserve(flag), s);
                for (int i = 0; i < n; i++) s.Items.Add(ReadObject());
                return s;
            }
            case ':':
            {
                var sl = new PySlice();
                Fill(Reserve(flag), sl);
                sl.Start = ReadObject(); sl.Stop = ReadObject(); sl.Step = ReadObject();
                return sl;
            }
            case 'c': return ReadCode(flag);

            case 'r':
            {
                int n = I32();
                if (n < 0 || n >= _refs.Count || _refs[n] == null)
                    throw new PycFormatException($"Bad marshal back-reference #{n} at offset 0x{pos0:X}");
                var o = _refs[n];
                if (o is PyBytes pb) pb.SharedRefs++;
                return o;
            }
        }
        throw new PycFormatException($"Unsupported marshal type '{(char.IsControl(type) ? "?" : type.ToString())}' (0x{b:X2}) at offset 0x{pos0:X}");
    }

    string Str(PyObj o) => o is PyStr s ? s.Value : o == null ? "" : o.Repr();

    string[] StrTuple(PyObj o)
    {
        if (o is PyTuple t) return t.Items.Select(Str).ToArray();
        if (o is PyList l) return l.Items.Select(Str).ToArray();
        return Array.Empty<string>();
    }

    PyBytes BytesObj(PyObj o, string what)
    {
        if (o is PyBytes b) return b;
        throw new PycFormatException($"Code object field '{what}' is not a bytes object (got {o?.TypeName ?? "NULL"})");
    }

    PyObj ReadCode(bool flag)
    {
        int idx = Reserve(flag);
        var c = new PyCode { Major = _major, Minor = _minor };
        AllCode.Add(c);

        c.ArgCount = I32();
        c.PosOnlyArgCount = I32();
        c.KwOnlyArgCount = I32();
        if (_minor < 11) c.NLocals = I32();
        c.StackSize = I32();
        c.Flags = I32();

        c.Code = BytesObj(ReadObject(), "co_code");
        if (!(ReadObject() is PyTuple consts)) throw new PycFormatException("Code object field 'co_consts' is not a tuple");
        c.Consts = consts.Items;
        c.Names = StrTuple(ReadObject());

        if (_minor < 11)
        {
            c.VarNames = StrTuple(ReadObject());
            c.FreeVars = StrTuple(ReadObject());
            c.CellVars = StrTuple(ReadObject());
        }
        else
        {
            c.LocalsPlusNames = StrTuple(ReadObject());
            c.LocalsPlusKinds = BytesObj(ReadObject(), "co_localspluskinds").Data;

            var vars = new List<string>(); var cells = new List<string>(); var frees = new List<string>();
            for (int i = 0; i < c.LocalsPlusNames.Length && i < c.LocalsPlusKinds.Length; i++)
            {
                byte k = c.LocalsPlusKinds[i];
                if ((k & 0x20) != 0) vars.Add(c.LocalsPlusNames[i]);
                if ((k & 0x40) != 0) cells.Add(c.LocalsPlusNames[i]);
                if ((k & 0x80) != 0) frees.Add(c.LocalsPlusNames[i]);
            }
            c.VarNames = vars.ToArray(); c.CellVars = cells.ToArray(); c.FreeVars = frees.ToArray();
        }

        c.Filename = Str(ReadObject());
        c.Name = Str(ReadObject());
        c.QualName = _minor >= 11 ? Str(ReadObject()) : c.Name;
        c.FirstLineNo = I32();
        c.LineTable = BytesObj(ReadObject(), "co_linetable").Data;
        if (_minor >= 11) c.ExceptionTable = BytesObj(ReadObject(), "co_exceptiontable").Data;

        foreach (var k in c.Consts)
            if (k is PyCode child && child.Parent == null) { child.Parent = c; c.Children.Add(child); }

        Fill(idx, c);
        return c;
    }
}
