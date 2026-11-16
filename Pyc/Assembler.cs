using System.Globalization;
using System.Numerics;
using System.Text;
using System.Text.RegularExpressions;

namespace Opcodex.Pyc;

public sealed class AsmException : Exception
{
    public AsmException(string message) : base(message) { }
}

public sealed class AsmInsn
{
    public int Op;
    public int Arg = -1;
    public string Name = "";
    public bool IsJump;

    public int TargetOffset = -1;

    public List<PyObj> AddConsts = new();
    public List<string> AddNames = new();
    public bool NeedsTableChange => AddConsts.Count > 0 || AddNames.Count > 0;
}

public static class Assembler
{
    static readonly Regex IntRx = new(@"^[+-]?(0[xX][0-9a-fA-F_]+|\d[\d_]*)$", RegexOptions.Compiled);
    static readonly Regex IdentRx = new(@"^[\p{L}_][\p{L}\p{N}_]*$", RegexOptions.Compiled);

    public static AsmInsn Parse(OpcodeTable t, PyCode co, string text)
    {
        text = (text ?? "").Trim();
        if (text.Length == 0) throw new AsmException("Empty instruction.");
        int sp = 0;
        while (sp < text.Length && !char.IsWhiteSpace(text[sp])) sp++;
        string mnemonic = text.Substring(0, sp).ToUpperInvariant();
        string rest = text.Substring(sp).Trim();

        if (!t.TryGetOpcode(mnemonic, out int op))
        {
            var near = t.AllNames().Where(n => n.Contains(mnemonic)).OrderBy(n => n).Take(6).ToList();
            throw new AsmException($"Unknown opcode '{mnemonic}' for Python {t.Major}.{t.Minor}." +
                                   (near.Count > 0 ? " Did you mean: " + string.Join(", ", near) + "?" : ""));
        }

        var a = new AsmInsn { Op = op, Name = mnemonic };
        int f = t.Flags(op);
        bool endAsyncFor = t.Minor >= 14 && mnemonic == "END_ASYNC_FOR";
        bool isJump = (f & (OpcodeTable.FJAbs | OpcodeTable.FJRel)) != 0 || endAsyncFor;

        if (!t.HasArg(op))
        {
            if (rest.Length > 0) throw new AsmException($"{mnemonic} takes no argument.");
            return a;
        }
        if (rest.Length == 0) throw new AsmException($"{mnemonic} requires an argument.");

        if ((f & OpcodeTable.FConst) != 0) a.Arg = ConstArg(co, a, rest);
        else if ((f & OpcodeTable.FName) != 0) a.Arg = NameArg(t, co, a, rest);
        else if (isJump)
        {
            a.IsJump = true;
            string r = rest;
            if (r.StartsWith("to ", StringComparison.OrdinalIgnoreCase)) r = r.Substring(3).Trim();
            bool at = r.StartsWith("@");
            if (at) r = r.Substring(1);
            if (!at && !r.StartsWith("0x", StringComparison.OrdinalIgnoreCase))
                throw new AsmException("Jump targets are written as a hex offset in co_code, e.g.  " + mnemonic + " 0x2C   (or @44 for decimal)");
            a.TargetOffset = (int)ParseInt(r);
            a.Arg = 0;
        }
        else if (mnemonic is "LOAD_FAST_LOAD_FAST" or "LOAD_FAST_BORROW_LOAD_FAST_BORROW" or "STORE_FAST_LOAD_FAST" or "STORE_FAST_STORE_FAST")
            a.Arg = DoubleLocalArg(t, co, rest);
        else if ((f & (OpcodeTable.FLocal | OpcodeTable.FFree)) != 0) a.Arg = LocalArg(t, co, mnemonic, rest);
        else if ((f & OpcodeTable.FCompare) != 0) a.Arg = CompareArg(t, rest);
        else if (mnemonic == "IS_OP") a.Arg = BoolWord(rest, "is", "is not");
        else if (mnemonic == "CONTAINS_OP") a.Arg = BoolWord(rest, "in", "not in");
        else if (mnemonic == "BINARY_OP" && !IntRx.IsMatch(rest))
        {
            int idx = Array.IndexOf(t.NbOps, rest);
            if (idx < 0) throw new AsmException($"Unknown BINARY_OP operator '{rest}'. Known: {string.Join(" ", t.NbOps)}");
            a.Arg = idx;
        }
        else a.Arg = RawArg(rest);

        if (a.Arg < 0 && !a.IsJump) throw new AsmException("Argument must be positive.");
        return a;
    }

    static long ParseInt(string s)
    {
        s = s.Replace("_", "");
        bool neg = s.StartsWith("-");
        if (s.StartsWith("+") || s.StartsWith("-")) s = s.Substring(1);
        long v;
        if (s.StartsWith("0x", StringComparison.OrdinalIgnoreCase))
        {
            if (!long.TryParse(s.Substring(2), NumberStyles.HexNumber, CultureInfo.InvariantCulture, out v))
                throw new AsmException($"Invalid number '{s}'.");
        }
        else if (!long.TryParse(s, NumberStyles.None, CultureInfo.InvariantCulture, out v))
            throw new AsmException($"Invalid number '{s}'.");
        return neg ? -v : v;
    }

    static int RawArg(string s)
    {
        if (!IntRx.IsMatch(s)) throw new AsmException($"Invalid argument '{s}' (expected a number, e.g. 12 or 0x0C).");
        long v = ParseInt(s);
        if (v < 0 || v > 0x7FFFFFFF) throw new AsmException("Argument out of range.");
        return (int)v;
    }

    static int ConstArg(PyCode co, AsmInsn a, string rest)
    {
        if (!rest.StartsWith("#") && IntRx.IsMatch(rest))
        {
            int idx = RawArg(rest);
            if (idx >= co.Consts.Count + a.AddConsts.Count)
                throw new AsmException($"Constant index {idx} is out of range (co_consts has {co.Consts.Count} entries). Use #value to add a new constant.");
            return idx;
        }
        string lit = rest.StartsWith("#") ? rest.Substring(1).Trim() : rest;
        PyObj value = LiteralParser.Parse(lit);
        return FindOrAddConst(co, a, value);
    }

    static bool SameConst(PyObj x, PyObj y) =>
        x != null && y != null && !(x is PyCode) && x.TypeName == y.TypeName && x.Repr() == y.Repr();

    static int FindOrAddConst(PyCode co, AsmInsn a, PyObj v)
    {
        for (int i = 0; i < co.Consts.Count; i++) if (SameConst(co.Consts[i], v)) return i;
        for (int i = 0; i < a.AddConsts.Count; i++) if (SameConst(a.AddConsts[i], v)) return co.Consts.Count + i;
        a.AddConsts.Add(v);
        return co.Consts.Count + a.AddConsts.Count - 1;
    }

    static int NameIndex(PyCode co, AsmInsn a, string name)
    {
        if (!IdentRx.IsMatch(name)) throw new AsmException($"'{name}' is not a valid identifier.");
        for (int i = 0; i < co.Names.Length; i++) if (co.Names[i] == name) return i;
        int k = a.AddNames.IndexOf(name);
        if (k >= 0) return co.Names.Length + k;
        a.AddNames.Add(name);
        return co.Names.Length + a.AddNames.Count - 1;
    }

    static int NameArg(OpcodeTable t, PyCode co, AsmInsn a, string rest)
    {
        if (IntRx.IsMatch(rest)) return RawArg(rest);

        int minor = t.Minor;
        string name = a.Name;

        bool flag = false;
        string id = rest;
        var m = Regex.Match(rest, @"^(?:(NULL(?:\|self)?)\s*\+\s*)?([^\s+]+)(?:\s*\+\s*(NULL(?:\|self)?))?$");
        if (m.Success) { id = m.Groups[2].Value; flag = m.Groups[1].Success || m.Groups[3].Success; }

        int idx = NameIndex(co, a, id);
        if (minor >= 11 && name == "LOAD_GLOBAL") return (idx << 1) | (flag ? 1 : 0);
        if (minor >= 12 && name == "LOAD_ATTR") return (idx << 1) | (flag ? 1 : 0);
        if (minor >= 12 && name == "LOAD_SUPER_ATTR")
            throw new AsmException("LOAD_SUPER_ATTR needs a raw argument ((name_index << 2) | flags).");
        if (minor >= 15 && name == "IMPORT_NAME") return idx << 2;
        if (flag) throw new AsmException($"{name} does not accept a NULL flag.");
        return idx;
    }

    static int LocalIndex(OpcodeTable t, PyCode co, string opName, string id)
    {
        id = id.Trim();
        if (IntRx.IsMatch(id)) return RawArg(id);
        if (t.Minor >= 11)
        {
            var arr = co.LocalsPlusNames ?? Array.Empty<string>();
            int i = Array.IndexOf(arr, id);
            if (i < 0) throw new AsmException($"'{id}' is not a local/cell/free variable of {co.Name}.");
            return i;
        }
        if (opName.Contains("FAST") || opName.Contains("LOCAL"))
        {
            int i = Array.IndexOf(co.VarNames, id);
            if (i < 0) throw new AsmException($"'{id}' is not a local variable of {co.Name} (co_varnames).");
            return i;
        }
        int c = Array.IndexOf(co.CellVars, id);
        if (c >= 0) return c;
        int fr = Array.IndexOf(co.FreeVars, id);
        if (fr >= 0) return co.CellVars.Length + fr;
        throw new AsmException($"'{id}' is not a cell/free variable of {co.Name}.");
    }

    static int LocalArg(OpcodeTable t, PyCode co, string opName, string rest) => LocalIndex(t, co, opName, rest);

    static int DoubleLocalArg(OpcodeTable t, PyCode co, string rest)
    {
        if (IntRx.IsMatch(rest)) return RawArg(rest);
        var parts = rest.Split(',');
        if (parts.Length != 2) throw new AsmException("Expected two local variables separated by a comma.");
        int a = LocalIndex(t, co, "FAST", parts[0]), b = LocalIndex(t, co, "FAST", parts[1]);
        if (a > 15 || b > 15) throw new AsmException("Both locals must have an index < 16 for this superinstruction.");
        return (a << 4) | b;
    }

    static int CompareArg(OpcodeTable t, string rest)
    {
        if (IntRx.IsMatch(rest)) return RawArg(rest);
        bool wrap = false;
        string sym = rest.Trim();
        var m = Regex.Match(sym, @"^bool\((.+)\)$");
        if (m.Success) { wrap = true; sym = m.Groups[1].Value.Trim(); }
        int idx = Array.IndexOf(t.Cmp, sym);
        if (idx < 0) throw new AsmException($"Unknown comparison '{rest}'. Known: {string.Join(" ", t.Cmp)}");
        if (t.Minor >= 13) return (idx << 5) | (wrap ? 16 : 0);
        if (wrap) throw new AsmException("bool(...) comparisons only exist in Python 3.13+.");
        return t.Minor == 12 ? idx << 4 : idx;
    }

    static int BoolWord(string rest, string zero, string one)
    {
        string r = Regex.Replace(rest.Trim(), @"\s+", " ");
        if (r == zero || r == "0") return 0;
        if (r == one || r == "1") return 1;
        throw new AsmException($"Expected '{zero}' or '{one}'.");
    }

    public static byte[] TryEncodeInPlace(OpcodeTable t, AsmInsn a, int offset, int oldWords)
    {
        int caches = t.Caches(a.Op);
        if (1 + caches != oldWords) return null;
        int arg = a.Arg;
        if (a.IsJump)
        {
            if (a.TargetOffset < 0) return null;
            try { arg = CodeEditor.JumpArg(t, a.Op, a.Name, offset, caches, a.TargetOffset); }
            catch (AsmException) { return null; }
        }
        if (t.HasArg(a.Op) ? (arg < 0 || arg > 255) : false) return null;
        var bytes = new byte[2 * oldWords];
        bytes[0] = (byte)a.Op;
        bytes[1] = (byte)(t.HasArg(a.Op) ? arg : 0);
        return bytes;
    }
}

public static class LiteralParser
{
    public static PyObj Parse(string s)
    {
        int p = 0;
        var v = Value(s, ref p);
        Ws(s, ref p);
        if (p != s.Length) throw new AsmException($"Unexpected text after the literal: '{s.Substring(p)}'");
        return v;
    }

    static void Ws(string s, ref int p) { while (p < s.Length && char.IsWhiteSpace(s[p])) p++; }

    static PyObj Value(string s, ref int p)
    {
        Ws(s, ref p);
        if (p >= s.Length) throw new AsmException("Missing constant value.");
        char c = s[p];

        if (c == '\'' || c == '"') return new PyStr(Str(s, ref p));
        if ((c == 'b' || c == 'B') && p + 1 < s.Length && (s[p + 1] == '\'' || s[p + 1] == '"'))
        {
            p++;
            string raw = Str(s, ref p);
            var bytes = new byte[raw.Length];
            for (int i = 0; i < raw.Length; i++)
            {
                if (raw[i] > 255) throw new AsmException("bytes literal can only contain characters < 256.");
                bytes[i] = (byte)raw[i];
            }
            return new PyBytes(bytes, -1);
        }
        if (c == '(')
        {
            p++;
            var t = new PyTuple();
            Ws(s, ref p);
            if (p < s.Length && s[p] == ')') { p++; return t; }
            while (true)
            {
                t.Items.Add(Value(s, ref p));
                Ws(s, ref p);
                if (p >= s.Length) throw new AsmException("Missing ')' in tuple.");
                if (s[p] == ',')
                {
                    p++; Ws(s, ref p);
                    if (p < s.Length && s[p] == ')') { p++; return t; }
                    continue;
                }
                if (s[p] == ')')
                {
                    p++;
                    if (t.Items.Count == 1) throw new AsmException("A one-element tuple needs a trailing comma: (x,)");
                    return t;
                }
                throw new AsmException($"Unexpected '{s[p]}' in tuple.");
            }
        }

        int st = p;
        while (p < s.Length && !char.IsWhiteSpace(s[p]) && s[p] != ',' && s[p] != ')') p++;
        string tok = s.Substring(st, p - st);
        switch (tok)
        {
            case "None": return PyNone.Instance;
            case "True": return PyBool.True;
            case "False": return PyBool.False;
            case "...": case "Ellipsis": return PyEllipsis.Instance;
        }
        string clean = tok.Replace("_", "");
        if (Regex.IsMatch(clean, @"^[+-]?0[xX][0-9a-fA-F]+$"))
        {
            bool neg = clean.StartsWith("-");
            string h = clean.TrimStart('+', '-').Substring(2);
            var v = BigInteger.Parse("0" + h, NumberStyles.HexNumber, CultureInfo.InvariantCulture);
            return new PyInt(neg ? -v : v);
        }
        if (Regex.IsMatch(clean, @"^[+-]?\d+$"))
            return new PyInt(BigInteger.Parse(clean, CultureInfo.InvariantCulture));
        if (clean.EndsWith("j") || clean.EndsWith("J"))
        {
            if (double.TryParse(clean.Substring(0, clean.Length - 1), NumberStyles.Float, CultureInfo.InvariantCulture, out double im))
                return new PyComplex(0, im);
        }
        if (double.TryParse(clean, NumberStyles.Float, CultureInfo.InvariantCulture, out double d)) return new PyFloat(d);
        throw new AsmException($"Cannot parse '{tok}' as a Python constant. Strings need quotes: 'text'.");
    }

    static string Str(string s, ref int p)
    {
        char q = s[p++];
        var sb = new StringBuilder();
        while (true)
        {
            if (p >= s.Length) throw new AsmException("Unterminated string literal.");
            char c = s[p++];
            if (c == q) break;
            if (c != '\\') { sb.Append(c); continue; }
            if (p >= s.Length) throw new AsmException("Unterminated string literal.");
            char e = s[p++];
            switch (e)
            {
                case 'n': sb.Append('\n'); break;
                case 'r': sb.Append('\r'); break;
                case 't': sb.Append('\t'); break;
                case '0': sb.Append('\0'); break;
                case '\\': sb.Append('\\'); break;
                case '\'': sb.Append('\''); break;
                case '"': sb.Append('"'); break;
                case 'x': sb.Append((char)Hex(s, ref p, 2)); break;
                case 'u': sb.Append((char)Hex(s, ref p, 4)); break;
                case 'U': sb.Append(char.ConvertFromUtf32(Hex(s, ref p, 8))); break;
                default: sb.Append('\\').Append(e); break;
            }
        }
        return sb.ToString();
    }

    static int Hex(string s, ref int p, int n)
    {
        if (p + n > s.Length || !int.TryParse(s.AsSpan(p, n), NumberStyles.HexNumber, CultureInfo.InvariantCulture, out int v))
            throw new AsmException("Invalid hexadecimal escape in string literal.");
        p += n;
        return v;
    }
}

public static class StackEffects
{

    public static int? Net(OpcodeTable t, string name, int arg)
    {
        if (arg < 0) arg = 0;
        switch (name)
        {
            case "NOP": case "RESUME": case "CACHE": case "EXTENDED_ARG": case "PRECALL": case "KW_NAMES":
            case "TO_BOOL": case "MAKE_CELL": case "COPY_FREE_VARS": case "SWAP": case "ROT_TWO": case "ROT_THREE":
            case "ROT_FOUR": case "UNARY_POSITIVE": case "UNARY_NEGATIVE": case "UNARY_NOT": case "UNARY_INVERT":
            case "GET_ITER": case "JUMP_FORWARD": case "JUMP_ABSOLUTE": case "JUMP_BACKWARD": case "JUMP_BACKWARD_NO_INTERRUPT":
            case "RETURN_CONST": case "LOAD_CLOSURE_DUMMY": case "FORMAT_SIMPLE": case "CONVERT_VALUE": case "SETUP_ANNOTATIONS":
                return 0;
            case "POP_TOP": case "RETURN_VALUE": case "STORE_NAME": case "STORE_FAST": case "STORE_GLOBAL":
            case "STORE_DEREF": case "POP_JUMP_IF_TRUE": case "POP_JUMP_IF_FALSE": case "POP_JUMP_IF_NONE":
            case "POP_JUMP_IF_NOT_NONE": case "POP_JUMP_FORWARD_IF_TRUE": case "POP_JUMP_FORWARD_IF_FALSE":
            case "POP_JUMP_BACKWARD_IF_TRUE": case "POP_JUMP_BACKWARD_IF_FALSE": case "COMPARE_OP": case "IS_OP":
            case "CONTAINS_OP": case "BINARY_OP": case "BINARY_SUBSCR": case "LIST_APPEND": case "SET_ADD":
            case "END_FOR": case "POP_ITER":
                return -1;
            case "STORE_ATTR": case "DELETE_SUBSCR": case "MAP_ADD": return -2;
            case "STORE_SUBSCR": return -3;
            case "DUP_TOP": case "COPY": case "PUSH_NULL": case "LOAD_CONST": case "LOAD_NAME": case "LOAD_FAST":
            case "LOAD_FAST_CHECK": case "LOAD_FAST_AND_CLEAR": case "LOAD_FAST_BORROW": case "LOAD_DEREF":
            case "LOAD_CLOSURE": case "LOAD_CLASSDEREF": case "LOAD_SMALL_INT": case "LOAD_COMMON_CONSTANT":
            case "LOAD_BUILD_CLASS": case "LOAD_ASSERTION_ERROR": case "LOAD_METHOD": case "FOR_ITER": case "LOAD_LOCALS":
                return 1;
            case "DUP_TOP_TWO": return 2;
            case "LOAD_GLOBAL": return t.Minor >= 11 ? 1 + (arg & 1) : 1;
            case "LOAD_ATTR": return t.Minor >= 12 ? (arg & 1) : 0;
            case "BUILD_TUPLE": case "BUILD_LIST": case "BUILD_SET": case "BUILD_STRING": return 1 - arg;
            case "BUILD_MAP": return 1 - 2 * arg;
            case "CALL_FUNCTION": return -arg;
            case "CALL_FUNCTION_KW": case "CALL_METHOD": case "CALL": return -arg - 1;
            case "CALL_KW": return -arg - 2;
            case "RAISE_VARARGS": return -arg;
            case "UNPACK_SEQUENCE": return arg - 1;
        }
        if (name.StartsWith("BINARY_") || name.StartsWith("INPLACE_")) return -1;
        if (name.StartsWith("LOAD_")) return 1;
        if (name.StartsWith("STORE_")) return -1;
        return null;
    }
}
