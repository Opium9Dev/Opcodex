namespace Opcodex.Pyc;

public enum StructOp { Replace, InsertBefore, Delete }

public sealed class PatchPlan
{
    public AsmInsn Asm;

    public byte[] InPlace;
    public bool IsStructural => InPlace == null;

    public string Reason = "";
}

public static class PatchService
{

    public static byte[] Bake(PycFile f, IEnumerable<(int FileOffset, byte[] Bytes)> patches)
    {
        var buf = (byte[])f.Raw.Clone();
        foreach (var (off, bytes) in patches)
        {
            if (off < 0 || off + bytes.Length > buf.Length) throw new PycFormatException($"Patch at file offset 0x{off:X} is outside the file.");
            Buffer.BlockCopy(bytes, 0, buf, off, bytes.Length);
        }
        return buf;
    }

    static bool HasExtPrefix(PycFile f, List<Instruction> insns, int index) =>
        index > 0 && insns[index - 1].Opcode == f.Opcodes.ExtendedArg && f.Opcodes.ExtendedArg >= 0;

    public static PatchPlan Plan(PycFile f, PyCode co, List<Instruction> insns, int index, string text)
    {
        var insn = insns[index];
        var a = Assembler.Parse(f.Opcodes, co, text);
        var plan = new PatchPlan { Asm = a };
        if (a.NeedsTableChange) { plan.Reason = "new constant / name added to the tables"; return plan; }
        if (HasExtPrefix(f, insns, index)) { plan.Reason = "the old instruction has an EXTENDED_ARG prefix"; return plan; }
        plan.InPlace = Assembler.TryEncodeInPlace(f.Opcodes, a, insn.Offset, 1 + insn.Caches);
        if (plan.InPlace == null) plan.Reason = "size or cache layout differs (argument > 255 or different inline cache count)";
        return plan;
    }

    public static PycFile ApplyStructural(PycFile baked, int codeIndex, int insnOffset, StructOp op, AsmInsn a, out string note)
    {
        var co = baked.AllCode[codeIndex];
        if (a != null)
        {
            foreach (var c in a.AddConsts) co.Consts.Add(c);
            if (a.AddNames.Count > 0) co.Names = co.Names.Concat(a.AddNames).ToArray();
        }

        var ed = new CodeEditor(co, baked.Opcodes);
        int idx = ed.IndexOfOffset(insnOffset);
        if (idx < 0) throw new AsmException($"No instruction at 0x{insnOffset:X}.");
        int oldLen = co.Code.Data.Length;

        switch (op)
        {
            case StructOp.Replace: ed.Replace(idx, new List<EInsn> { ed.FromAsm(a) }); break;
            case StructOp.InsertBefore: ed.Insert(idx, new List<EInsn> { ed.FromAsm(a) }); break;
            case StructOp.Delete: ed.Delete(idx); break;
        }
        var res = ed.Commit();

        co.Code = new PyBytes(res.Code, -1);
        co.LineTable = res.LineTable;
        if (co.Minor >= 11) co.ExceptionTable = res.ExceptionTable;
        co.StackSize += res.StackExtra;

        note = $"co_code {oldLen} → {res.Code.Length} bytes" +
               (a != null && a.AddConsts.Count > 0 ? $", +{a.AddConsts.Count} const(s)" : "") +
               (a != null && a.AddNames.Count > 0 ? $", +{a.AddNames.Count} name(s)" : "") +
               (res.StackExtra > 0 ? $", stacksize +{res.StackExtra}" : "");

        byte[] raw = MarshalWriter.Build(baked);
        return PycFile.Parse(raw, baked.Path);
    }

    public static PycFile Rebuild(PycFile baked, bool clearCheckSource)
    {
        byte[] raw = MarshalWriter.Build(baked, clearCheckSource);
        return PycFile.Parse(raw, baked.Path);
    }

    public static string InvertedName(string name)
    {

        if (name.Contains("_IF_NOT_NONE")) return name.Replace("_IF_NOT_NONE", "_IF_NONE");
        if (name.Contains("_IF_NONE")) return name.Replace("_IF_NONE", "_IF_NOT_NONE");
        if (name.Contains("_IF_TRUE")) return name.Replace("_IF_TRUE", "_IF_FALSE");
        if (name.Contains("_IF_FALSE")) return name.Replace("_IF_FALSE", "_IF_TRUE");
        return null;
    }

    public static byte[] InvertJump(PycFile f, PyCode co, Instruction insn, out string newName, out string error)
    {
        newName = null; error = null;
        var t = f.Opcodes;
        string inv = InvertedName(insn.Name);
        if (inv == null || insn.Target == null) { error = $"{insn.Name} is not a conditional jump that can be inverted."; return null; }
        if (!t.TryGetOpcode(inv, out int op2)) { error = $"{inv} does not exist in Python {t.Major}.{t.Minor}."; return null; }
        if (t.Caches(op2) != insn.Caches) { error = $"{inv} has a different inline cache size."; return null; }
        if (t.HasArg(op2) != t.HasArg(insn.Opcode)) { error = $"{inv} has a different argument layout."; return null; }

        byte[] bytes = new byte[insn.Length];
        Buffer.BlockCopy(co.Code.Data, insn.Offset, bytes, 0, bytes.Length);
        bytes[0] = (byte)op2;
        newName = inv;
        return bytes;
    }
}
