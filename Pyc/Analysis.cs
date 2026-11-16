using System.Text;

namespace Opcodex.Pyc;

public sealed class CfgBlock
{
    public int Id, Start, End;
    public List<Instruction> Insns = new();
    public List<(int To, string Kind)> Succ = new();
    public bool IsHandler;
}

public static class Cfg
{
    static bool IsUnconditional(string n) =>
        n.StartsWith("JUMP_FORWARD") || n.StartsWith("JUMP_BACKWARD") || n == "JUMP_ABSOLUTE" || n == "JUMP";

    static bool EndsFlow(string n) =>
        n.StartsWith("RETURN") || n == "RAISE_VARARGS" || n == "RERAISE";

    public static List<CfgBlock> Build(PyCode co, OpcodeTable t, List<Instruction> insns)
    {
        var res = new List<CfgBlock>();
        if (insns.Count == 0) return res;

        var leaders = new SortedSet<int> { insns[0].Offset };
        var handlers = new HashSet<int>();
        for (int k = 0; k < insns.Count; k++)
        {
            var i = insns[k];
            if (i.Target is int tg) leaders.Add(tg);
            if ((i.Target != null || EndsFlow(i.Name)) && k + 1 < insns.Count) leaders.Add(insns[k + 1].Offset);
        }
        if (t.Minor >= 11 && co.ExceptionTable.Length > 0)
        {
            try
            {
                foreach (var e in LineTables.DecodeExc(co.ExceptionTable))
                {
                    leaders.Add(e.Target * 2); handlers.Add(e.Target * 2);
                    leaders.Add(e.Start * 2); leaders.Add(e.End * 2);
                }
            }
            catch (Exception) {  }
        }

        CfgBlock cur = null;
        foreach (var i in insns)
        {
            if (cur == null || leaders.Contains(i.Offset))
            {
                cur = new CfgBlock { Id = res.Count, Start = i.Offset, IsHandler = handlers.Contains(i.Offset) };
                res.Add(cur);
            }
            cur.Insns.Add(i);
            cur.End = i.Offset + i.Length;
        }

        var byStart = res.ToDictionary(b => b.Start, b => b.Id);
        for (int n = 0; n < res.Count; n++)
        {
            var b = res[n];
            var last = b.Insns[^1];
            if (last.Target is int tg && byStart.TryGetValue(tg, out int to)) b.Succ.Add((to, "jump"));
            bool falls = !IsUnconditional(last.Name) && !EndsFlow(last.Name);
            if (falls && n + 1 < res.Count) b.Succ.Add((res[n + 1].Id, "fall"));
        }

        if (t.Minor >= 11 && co.ExceptionTable.Length > 0)
        {
            try
            {
                foreach (var e in LineTables.DecodeExc(co.ExceptionTable))
                {
                    if (!byStart.TryGetValue(e.Target * 2, out int h)) continue;
                    foreach (var b in res)
                        if (b.Start >= e.Start * 2 && b.Start < e.End * 2 && !b.Succ.Contains((h, "exc")))
                            b.Succ.Add((h, "exc"));
                }
            }
            catch (Exception) { }
        }
        return res;
    }

    public static string ToText(PyCode co, List<CfgBlock> blocks)
    {
        var sb = new StringBuilder();
        sb.AppendLine($"; Control flow graph of {co.QualName}: {blocks.Count} block(s)");
        foreach (var b in blocks)
        {
            sb.AppendLine();
            sb.AppendLine($"B{b.Id}  [0x{b.Start:X4} - 0x{b.End:X4})" + (b.IsHandler ? "   (exception handler)" : ""));
            foreach (var i in b.Insns)
                sb.AppendLine($"    0x{i.Offset:X4}  {i.Name,-28} {(i.HasArg ? i.Arg.ToString() : ""),-6} {i.Operand}");
            if (b.Succ.Count == 0) sb.AppendLine("    -> (exit)");
            foreach (var (to, kind) in b.Succ) sb.AppendLine($"    -> B{to}  ({kind})");
        }
        return sb.ToString();
    }

    public static string ToDot(PyCode co, List<CfgBlock> blocks)
    {
        var sb = new StringBuilder();
        sb.AppendLine("digraph cfg {");
        sb.AppendLine("  node [shape=box, fontname=\"Consolas\", fontsize=10];");
        foreach (var b in blocks)
        {
            var lab = new StringBuilder($"B{b.Id} 0x{b.Start:X}\\l");
            foreach (var i in b.Insns)
                lab.Append($"{i.Offset:X4} {i.Name} {(i.HasArg ? i.Arg.ToString() : "")} {Esc(i.Operand)}\\l");
            sb.AppendLine($"  B{b.Id} [label=\"{lab}\"" + (b.IsHandler ? ", style=dashed" : "") + "];");
        }
        foreach (var b in blocks)
            foreach (var (to, kind) in b.Succ)
                sb.AppendLine($"  B{b.Id} -> B{to} [label=\"{kind}\"" + (kind == "exc" ? ", style=dashed" : "") + "];");
        sb.AppendLine("}");
        return sb.ToString();
    }

    static string Esc(string s) => (s ?? "").Replace("\\", "\\\\").Replace("\"", "\\\"");
}

public static class XRefs
{

    public static List<(Instruction Insn, string Why)> For(List<Instruction> insns, Instruction sel)
    {
        var res = new List<(Instruction, string)>();
        if (sel == null) return res;
        if (sel.RefKind != '\0' && sel.RefIndex >= 0)
        {
            string what = sel.RefKind == 'c' ? "constant" : sel.RefKind == 'n' ? "name" : "local";
            foreach (var i in insns)
                if (i.RefKind == sel.RefKind && i.RefIndex == sel.RefIndex)
                    res.Add((i, $"uses {what} #{sel.RefIndex}"));
        }
        foreach (var i in insns)
            if (i.Target == sel.Offset) res.Add((i, $"jumps to 0x{sel.Offset:X}"));
        if (sel.Target is int tg)
        {
            var dest = insns.FirstOrDefault(i => i.Offset == tg);
            if (dest != null) res.Add((dest, "jump target of the selection"));
        }
        return res;
    }
}

public static class InsnSearch
{
    public static bool Matches(Instruction i, string q)
    {
        if (string.IsNullOrWhiteSpace(q)) return false;
        q = q.Trim();
        var cmp = StringComparison.OrdinalIgnoreCase;
        return i.Name.Contains(q, cmp) || (i.Operand ?? "").Contains(q, cmp) || (i.Comment ?? "").Contains(q, cmp)
               || $"0x{i.Offset:X4}".Contains(q, cmp);
    }

    public static bool TryParseOffset(string s, out int off)
    {
        off = 0;
        s = (s ?? "").Trim();
        if (s.StartsWith("@")) return int.TryParse(s.Substring(1), out off);
        if (s.StartsWith("0x", StringComparison.OrdinalIgnoreCase)) s = s.Substring(2);
        return int.TryParse(s, System.Globalization.NumberStyles.HexNumber, System.Globalization.CultureInfo.InvariantCulture, out off);
    }
}
