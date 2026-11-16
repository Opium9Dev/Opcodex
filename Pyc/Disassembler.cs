using System.Text;

namespace Opcodex.Pyc;

public sealed class Instruction
{

    public int Offset;
    public int Opcode;
    public string Name = "";
    public bool HasArg;

    public int Arg = -1;
    public byte[] Bytes = Array.Empty<byte>();

    public int Caches;
    public int? Target;
    public string Operand = "";
    public string Comment = "";

    public char RefKind;
    public int RefIndex = -1;

    public int FileOffset;
    public int Length => 2 + 2 * Caches;
}

public static class Disassembler
{
    static readonly string[] MakeFunctionFlags = { "defaults", "kwdefaults", "annotations", "closure", "annotate" };
    static readonly string[] Converters = { "", "str", "repr", "ascii" };
    static readonly string[] SpecialNames = { "__enter__", "__exit__", "__aenter__", "__aexit__" };

    static readonly string[] CommonConstants =
    {
        "AssertionError", "NotImplementedError", "tuple", "all", "any",
        "list", "set", "None", "''", "True", "False", "-1", "frozenset", "()",
    };

    public static List<Instruction> Disassemble(PyCode co, OpcodeTable t, bool showCaches = false)
    {
        var res = new List<Instruction>();
        byte[] code = co.Code.Data;
        int ext = 0;
        int i = 0;
        while (i < code.Length)
        {
            if (i + 1 >= code.Length)
            {

                res.Add(new Instruction
                {
                    Offset = i, Opcode = code[i], Name = ".byte", Bytes = new[] { code[i] },
                    Operand = $"(0x{code[i]:X2})", Comment = "; truncated instruction",
                    FileOffset = co.Code.FileOffset + i,
                });
                break;
            }
            int op = code[i];
            int raw = code[i + 1];
            bool known = t.IsKnown(op);
            var ins = new Instruction
            {
                Offset = i, Opcode = op, Name = t.Name(op), HasArg = t.HasArg(op),
                Bytes = new[] { code[i], code[i + 1] }, FileOffset = co.Code.FileOffset + i,
            };
            if (ins.HasArg)
            {
                unchecked
                {
                    ins.Arg = raw | ext;
                    ext = op == t.ExtendedArg ? ins.Arg << 8 : 0;
                }
            }
            else ext = 0;

            ins.Caches = known ? t.Caches(op) : 0;

            int maxCaches = (code.Length - i - 2) / 2;
            if (ins.Caches > maxCaches) ins.Caches = maxCaches;

            if (!known) ins.Comment = "; unknown opcode for Python " + t.Major + "." + t.Minor;
            else if (ins.Caches > 0) ins.Comment = $"; +{ins.Caches} cache entr{(ins.Caches == 1 ? "y" : "ies")}";

            if (ins.HasArg) Resolve(ins, co, t);
            res.Add(ins);

            if (showCaches)
            {
                for (int k = 0; k < ins.Caches; k++)
                {
                    int o = i + 2 + 2 * k;
                    res.Add(new Instruction
                    {
                        Offset = o, Opcode = code[o], Name = "CACHE", Bytes = new[] { code[o], code[o + 1] },
                        FileOffset = co.Code.FileOffset + o,
                    });
                }
            }
            i += ins.Length;
        }
        return res;
    }

    static string Paren(string s) => s.Length == 0 ? "" : "(" + s + ")";

    static string ConstRepr(PyCode co, int arg) =>
        arg >= 0 && arg < co.Consts.Count ? PyObj.Trunc(co.Consts[arg].Repr(), 200) : $"<const #{arg} out of range>";

    static string NameAt(PyCode co, int idx) =>
        idx >= 0 && idx < co.Names.Length ? co.Names[idx] : $"<name #{idx} out of range>";

    static string LocalAt(PyCode co, int minor, string opName, int arg)
    {
        string[] arr;
        int idx = arg;
        if (minor >= 11) arr = co.LocalsPlusNames ?? Array.Empty<string>();
        else if (opName.Contains("FAST") || opName.Contains("LOCAL")) arr = co.VarNames;
        else
        {

            if (arg < co.CellVars.Length) return co.CellVars[arg];
            idx = arg - co.CellVars.Length;
            arr = co.FreeVars;
        }
        return idx >= 0 && idx < arr.Length ? arr[idx] : $"<local #{arg} out of range>";
    }

    static void Resolve(Instruction ins, PyCode co, OpcodeTable t)
    {
        int op = ins.Opcode, arg = ins.Arg, minor = t.Minor;
        string name = ins.Name;
        int f = t.Flags(op);

        if ((f & OpcodeTable.FConst) != 0)
        {
            ins.RefKind = 'c'; ins.RefIndex = arg;
            ins.Operand = Paren(ConstRepr(co, arg));
            return;
        }

        if ((f & OpcodeTable.FName) != 0)
        {
            int idx = arg;
            string suffix = "";
            string prefix = "";
            if (minor >= 11 && name == "LOAD_GLOBAL")
            {
                idx = arg >> 1;
                if ((arg & 1) != 0) { if (minor >= 13) suffix = " + NULL"; else prefix = "NULL + "; }
            }
            else if (minor >= 12 && name == "LOAD_ATTR")
            {
                idx = arg >> 1;
                if ((arg & 1) != 0) { if (minor >= 13) suffix = " + NULL|self"; else prefix = "NULL|self + "; }
            }
            else if (minor >= 12 && name == "LOAD_SUPER_ATTR")
            {
                idx = arg >> 2;
                if ((arg & 1) != 0) { if (minor >= 13) suffix = " + NULL|self"; else prefix = "NULL|self + "; }
            }
            else if (minor >= 15 && name == "IMPORT_NAME")
            {
                idx = arg >> 2;
                if ((arg & 1) != 0) suffix = " + lazy";
                else if ((arg & 2) != 0) suffix = " + eager";
            }
            ins.RefKind = 'n'; ins.RefIndex = idx;
            ins.Operand = Paren(prefix + NameAt(co, idx) + suffix);
            return;
        }

        bool endAsyncFor = minor >= 14 && name == "END_ASYNC_FOR";
        if ((f & OpcodeTable.FJAbs) != 0)
        {
            int target = minor >= 10 ? arg * 2 : arg;
            ins.Target = target;
            ins.Operand = $"(to 0x{target:X})";
            return;
        }
        if ((f & OpcodeTable.FJRel) != 0 || endAsyncFor)
        {
            int scale = minor >= 10 ? 2 : 1;
            bool backward = minor >= 11 && (name.Contains("BACKWARD") || endAsyncFor);
            int signed = backward ? -arg : arg;
            int target = ins.Offset + 2 + signed * scale;
            if (minor >= 12) target += 2 * ins.Caches;
            ins.Target = target;
            ins.Operand = $"({(endAsyncFor ? "from" : "to")} 0x{target:X})";
            return;
        }

        if (name == "LOAD_FAST_LOAD_FAST" || name == "LOAD_FAST_BORROW_LOAD_FAST_BORROW" ||
            name == "STORE_FAST_LOAD_FAST" || name == "STORE_FAST_STORE_FAST")
        {
            ins.RefKind = 'l'; ins.RefIndex = arg >> 4;
            ins.Operand = Paren(LocalAt(co, minor, "FAST", arg >> 4) + ", " + LocalAt(co, minor, "FAST", arg & 15));
            return;
        }
        if ((f & (OpcodeTable.FLocal | OpcodeTable.FFree)) != 0)
        {
            ins.RefKind = 'l'; ins.RefIndex = arg;
            ins.Operand = Paren(LocalAt(co, minor, name, arg));
            return;
        }

        string s = "";
        if ((f & OpcodeTable.FCompare) != 0)
        {
            int ci = minor >= 13 ? arg >> 5 : minor == 12 ? arg >> 4 : arg;
            s = ci >= 0 && ci < t.Cmp.Length ? t.Cmp[ci] : "BAD";
            if (minor >= 13 && (arg & 16) != 0) s = $"bool({s})";
        }
        else if (name == "FORMAT_VALUE")
        {
            s = Converters[arg & 3];
            if ((arg & 4) != 0) s += (s.Length > 0 ? ", " : "") + "with format";
        }
        else if (name == "CONVERT_VALUE") s = Converters[arg & 3];
        else if (name == "MAKE_FUNCTION" && minor <= 12) s = FlagList(arg, 4);
        else if (name == "SET_FUNCTION_ATTRIBUTE") s = FlagList(arg, 5);
        else if (name == "BINARY_OP") s = arg >= 0 && arg < t.NbOps.Length ? t.NbOps[arg] : "";
        else if (name == "CALL_INTRINSIC_1") s = OpcodeTable.Intrinsic1Name(arg) ?? "";
        else if (name == "CALL_INTRINSIC_2") s = OpcodeTable.Intrinsic2Name(arg) ?? "";
        else if (name == "LOAD_SMALL_INT") s = arg.ToString();
        else if (name == "LOAD_COMMON_CONSTANT")
        {
            int limit = minor >= 15 ? CommonConstants.Length : 5;
            s = arg >= 0 && arg < limit ? CommonConstants[arg] : "";
        }
        else if (name == "LOAD_SPECIAL") s = arg >= 0 && arg < SpecialNames.Length ? SpecialNames[arg] : "";
        else if (name == "IS_OP") s = arg != 0 ? "is not" : "is";
        else if (name == "CONTAINS_OP") s = arg != 0 ? "not in" : "in";
        ins.Operand = Paren(s);
    }

    static string FlagList(int arg, int count)
    {
        var parts = new List<string>();
        for (int i = 0; i < count; i++) if ((arg & (1 << i)) != 0) parts.Add(MakeFunctionFlags[i]);
        return string.Join(", ", parts);
    }
}

public static class DisasmExport
{
    public static string Hex(byte[] b) => BitConverter.ToString(b).Replace('-', ' ');

    public static string Format(PycFile f)
    {
        var sb = new StringBuilder();
        sb.AppendLine($"; {System.IO.Path.GetFileName(f.Path)}");
        sb.AppendLine($"; Python {f.VersionText}, magic {f.MagicNumber}, {f.AllCode.Count} code object(s)");
        foreach (var c in f.AllCode)
        {
            sb.AppendLine();
            sb.AppendLine($"; ===== {c.QualName} (file {PyObj.StrRepr(c.Filename)}, line {c.FirstLineNo}) =====");
            foreach (var i in Disassembler.Disassemble(c, f.Opcodes))
            {
                sb.Append($"0x{i.Offset:X4}  {Hex(i.Bytes),-5}  {i.Name,-30} {(i.HasArg ? i.Arg.ToString() : ""),-8} {i.Operand}");
                if (i.Comment.Length > 0) sb.Append("  ").Append(i.Comment);
                sb.AppendLine();
            }
        }
        return sb.ToString();
    }
}
