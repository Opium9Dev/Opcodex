namespace Opcodex.Pyc;

public sealed class EInsn
{
    public int Op, Arg, Caches;
    public byte[] Cache = Array.Empty<byte>();
    public string Name = "";

    public int OldStart = -1, OldMain = -1;

    public int MapStart = -1;

    public EInsn Target;

    public EInsn LocSrc;

    public int Ext, Start, Main;
    public bool IsNew => OldStart < 0;
}

public sealed class EditResult
{
    public byte[] Code = Array.Empty<byte>();
    public byte[] LineTable = Array.Empty<byte>();
    public byte[] ExceptionTable = Array.Empty<byte>();
    public int StackExtra;

    public HashSet<int> NewOffsets = new();
}

public sealed class CodeEditor
{
    readonly PyCode _co;
    readonly OpcodeTable _t;
    readonly int _oldLen;
    public readonly List<EInsn> Insns = new();

    public CodeEditor(PyCode co, OpcodeTable t)
    {
        _co = co; _t = t;
        byte[] code = co.Code.Data;
        _oldLen = code.Length;
        if (code.Length % 2 != 0) throw new PycFormatException("co_code has an odd length: cannot edit it.");
        Decode(code);
    }

    public static bool IsJumpOp(OpcodeTable t, int op)
    {
        int f = t.Flags(op);
        return (f & (OpcodeTable.FJAbs | OpcodeTable.FJRel)) != 0 || (t.Minor >= 14 && t.Name(op) == "END_ASYNC_FOR");
    }

    static bool IsAbs(OpcodeTable t, int op) => (t.Flags(op) & OpcodeTable.FJAbs) != 0;

    static bool IsBackward(OpcodeTable t, string name) =>
        t.Minor >= 11 && (name.Contains("BACKWARD") || (t.Minor >= 14 && name == "END_ASYNC_FOR"));

    public static int JumpArg(OpcodeTable t, int op, string name, int main, int caches, int target)
    {
        int scale = t.Minor >= 10 ? 2 : 1;
        if (IsAbs(t, op))
        {
            if (target % scale != 0) throw new AsmException($"Jump target 0x{target:X} is not aligned.");
            return target / scale;
        }
        int baseOff = main + 2 + (t.Minor >= 12 ? 2 * caches : 0);
        bool back = IsBackward(t, name);
        int d = back ? baseOff - target : target - baseOff;
        if (d < 0)
            throw new AsmException($"{name} cannot jump {(back ? "forward" : "backward")} to 0x{target:X} (this opcode only jumps {(back ? "backward" : "forward")}).");
        if (d % scale != 0) throw new AsmException($"Jump distance to 0x{target:X} is not a multiple of {scale}.");
        return d / scale;
    }

    static int ExtNeeded(int arg) => arg < 0x100 ? 0 : arg < 0x10000 ? 1 : arg < 0x1000000 ? 2 : 3;

    void Decode(byte[] code)
    {
        int i = 0, ext = 0, start = -1;
        unchecked
        {
            while (i < code.Length)
            {
                if (start < 0) start = i;
                int op = code[i], raw = code[i + 1];
                bool has = _t.HasArg(op);
                int arg = has ? (raw | ext) : -1;
                if (op == _t.ExtendedArg) { ext = arg << 8; i += 2; continue; }
                ext = 0;

                int caches = _t.IsKnown(op) ? _t.Caches(op) : 0;
                int maxCaches = (code.Length - i - 2) / 2;
                if (caches > maxCaches) caches = maxCaches;
                var e = new EInsn
                {
                    Op = op, Arg = arg, Caches = caches, Name = _t.Name(op),
                    OldStart = start, OldMain = i,
                    Cache = code[(i + 2)..(i + 2 + 2 * caches)],
                };
                Insns.Add(e);
                i += 2 + 2 * caches;
                start = -1;
            }
        }
        if (start >= 0) throw new PycFormatException("co_code ends with a dangling EXTENDED_ARG: cannot edit it.");

        var byStart = new Dictionary<int, EInsn>();
        foreach (var e in Insns) byStart[e.OldStart] = e;

        int scale = _t.Minor >= 10 ? 2 : 1;
        foreach (var e in Insns)
        {
            if (!IsJumpOp(_t, e.Op)) continue;
            int target;
            if (IsAbs(_t, e.Op)) target = e.Arg * scale;
            else
            {
                int signed = IsBackward(_t, e.Name) ? -e.Arg : e.Arg;
                target = e.OldMain + 2 + signed * scale;
                if (_t.Minor >= 12) target += 2 * e.Caches;
            }
            if (!byStart.TryGetValue(target, out var tgt))
                throw new PycFormatException($"The jump at 0x{e.OldMain:X} targets 0x{target:X}, which is not the start of an instruction. " +
                                             "This code cannot be restructured (anti-disassembly trick?). In-place patches still work.");
            e.Target = tgt;
        }
    }

    public int IndexOfOffset(int offset)
    {
        for (int k = 0; k < Insns.Count; k++)
        {
            var e = Insns[k];
            if (e.OldStart < 0) continue;
            if (offset >= e.OldStart && offset < e.OldMain + 2 + 2 * e.Caches) return k;
        }
        return -1;
    }

    public EInsn FromAsm(AsmInsn a)
    {
        var e = new EInsn
        {
            Op = a.Op, Name = a.Name, Arg = t_HasArg(a.Op) ? a.Arg : -1,
            Caches = _t.Caches(a.Op),
        };
        e.Cache = new byte[2 * e.Caches];
        if (a.IsJump)
        {
            EInsn tgt = null;
            foreach (var x in Insns) if (x.OldStart == a.TargetOffset) { tgt = x; break; }
            if (tgt == null)
                throw new AsmException($"Jump target 0x{a.TargetOffset:X} is not the start of an instruction.");
            e.Target = tgt;
            e.Arg = 0;
        }
        return e;
    }

    bool t_HasArg(int op) => _t.HasArg(op);

    void Retarget(EInsn from, EInsn to)
    {
        foreach (var x in Insns) if (x.Target == from) x.Target = to;
    }

    static EInsn LocOf(EInsn x) => x.OldMain >= 0 ? x : x.LocSrc;

    public void Insert(int idx, List<EInsn> news)
    {
        var x = Insns[idx];
        foreach (var n in news) if (n.Target == x) n.Target = news[0];
        Retarget(x, news[0]);
        foreach (var n in news) n.LocSrc ??= LocOf(x);
        Insns.InsertRange(idx, news);
    }

    public void Replace(int idx, List<EInsn> news)
    {
        var x = Insns[idx];
        foreach (var n in news) if (n.Target == x) n.Target = news[0];
        Retarget(x, news[0]);
        int mapKey = x.OldStart >= 0 ? x.OldStart : x.MapStart;
        foreach (var n in news) { n.MapStart = mapKey; n.LocSrc ??= LocOf(x); }
        Insns.RemoveAt(idx);
        Insns.InsertRange(idx, news);
    }

    public void Delete(int idx)
    {
        if (idx < 0 || idx >= Insns.Count) throw new AsmException("No instruction to delete.");
        if (idx == Insns.Count - 1) throw new AsmException("The last instruction cannot be deleted.");
        var x = Insns[idx];
        Retarget(x, Insns[idx + 1]);
        Insns.RemoveAt(idx);
    }

    public EditResult Commit()
    {
        var present = new HashSet<EInsn>(Insns);
        foreach (var e in Insns)
            if (e.Target != null && !present.Contains(e.Target))
                throw new AsmException("A jump targets an instruction that was removed.");

        foreach (var e in Insns) e.Ext = _t.HasArg(e.Op) ? ExtNeeded(Math.Max(e.Arg, 0)) : 0;
        int total = 0;
        for (int iter = 0; iter < 64; iter++)
        {
            int pos = 0;
            foreach (var e in Insns)
            {
                e.Start = pos;
                e.Main = pos + 2 * e.Ext;
                pos += 2 * (e.Ext + 1 + e.Caches);
            }
            total = pos;
            bool changed = false;
            foreach (var e in Insns)
            {
                if (e.Target == null) continue;
                e.Arg = JumpArg(_t, e.Op, e.Name, e.Main, e.Caches, e.Target.Start);
                int need = ExtNeeded(e.Arg);
                if (need > e.Ext) { e.Ext = need; changed = true; }
            }
            if (!changed) break;
            if (iter == 63) throw new AsmException("Jump relaxation did not converge.");
        }

        var code = new List<byte>(total);
        foreach (var e in Insns)
        {
            for (int k = e.Ext; k >= 1; k--)
            {
                code.Add((byte)_t.ExtendedArg);
                code.Add((byte)((e.Arg >> (8 * k)) & 0xFF));
            }
            code.Add((byte)e.Op);
            code.Add((byte)(_t.HasArg(e.Op) ? (e.Arg & 0xFF) : 0));
            code.AddRange(e.Cache);
        }

        var res = new EditResult { Code = code.ToArray() };

        int oldUnits = _oldLen / 2;
        Loc[] oldLoc = LineTables.Decode(_co, oldUnits);
        Loc L(int u) => oldLoc.Length == 0 ? Loc.None : oldLoc[Math.Clamp(u, 0, oldLoc.Length - 1)];
        var nl = new List<Loc>(total / 2);
        foreach (var e in Insns)
        {
            var src = e.LocSrc ?? e;
            if (src.OldMain < 0) src = null;
            int m = src != null ? src.OldMain / 2 : -1;
            Loc main = src != null ? L(m) : (nl.Count > 0 ? nl[^1] : Loc.None);
            for (int k = 0; k <= e.Ext; k++) nl.Add(main);
            for (int k = 0; k < e.Caches; k++) nl.Add(src == e ? L(m + 1 + k) : main);
        }
        res.LineTable = LineTables.Encode(nl.ToArray(), _co);

        if (_t.Minor >= 11 && _co.ExceptionTable.Length > 0)
        {
            var gm = new Dictionary<int, int>();
            int pending = -1;
            foreach (var e in Insns)
            {
                if (e.OldStart < 0 && e.MapStart < 0) { if (pending < 0) pending = e.Start; }
                else
                {
                    int key = e.OldStart >= 0 ? e.OldStart : e.MapStart;
                    if (!gm.ContainsKey(key)) gm[key] = pending >= 0 ? pending : e.Start;
                    pending = -1;
                }
            }
            gm[_oldLen] = pending >= 0 ? pending : total;

            int Map(int unit)
            {
                int o = unit * 2;
                while (o <= _oldLen && !gm.ContainsKey(o)) o += 2;
                return gm.TryGetValue(o, out int v) ? v / 2 : total / 2;
            }

            var entries = new List<ExcEntry>();
            foreach (var x in LineTables.DecodeExc(_co.ExceptionTable))
                entries.Add(new ExcEntry(Map(x.Start), Map(x.End), Map(x.Target), x.Depth, x.LastI));
            res.ExceptionTable = LineTables.EncodeExc(entries);
        }

        int extra = 0;
        foreach (var e in Insns)
        {
            if (!e.IsNew) continue;
            res.NewOffsets.Add(e.Main);
            extra += Math.Max(0, StackEffects.Net(_t, e.Name, e.Arg) ?? 1);
        }
        res.StackExtra = extra;
        return res;
    }
}
