namespace Opcodex.Pyc;

public readonly record struct Loc(int Line, int EndLine, int Col, int EndCol)
{
    public static readonly Loc None = new(-1, -1, -1, -1);
}

public readonly record struct ExcEntry(int Start, int End, int Target, int Depth, bool LastI);

public static class LineTables
{

    public static Loc[] Decode(PyCode co, int units)
    {
        var res = new Loc[units];
        Array.Fill(res, Loc.None);
        try
        {
            if (co.Minor >= 11) DecodeLocation(co.LineTable, co.FirstLineNo, res);
            else if (co.Minor == 10) Decode310(co.LineTable, co.FirstLineNo, res);
            else DecodeLnotab(co.LineTable, co.FirstLineNo, res);
        }
        catch (IndexOutOfRangeException)
        {

        }
        return res;
    }

    public static byte[] Encode(Loc[] locs, PyCode co)
    {
        if (co.Minor >= 11) return EncodeLocation(locs, co.FirstLineNo);
        if (co.Minor == 10) return Encode310(locs, co.FirstLineNo);
        return EncodeLnotab(locs, co.FirstLineNo);
    }

    static void DecodeLnotab(byte[] tab, int first, Loc[] res)
    {
        var changes = new List<(int addr, int line)>();
        int addr = 0, line = first;
        for (int i = 0; i + 1 < tab.Length; i += 2)
        {
            addr += tab[i];
            line += (sbyte)tab[i + 1];
            changes.Add((addr, line));
        }
        int p = 0, cur = first;
        for (int u = 0; u < res.Length; u++)
        {
            while (p < changes.Count && changes[p].addr <= 2 * u) { cur = changes[p].line; p++; }
            res[u] = new Loc(cur, cur, -1, -1);
        }
    }

    static byte[] EncodeLnotab(Loc[] locs, int first)
    {
        var o = new List<byte>();
        int lastAddr = 0, lastLine = first;
        for (int u = 0; u < locs.Length; u++)
        {
            int ln = locs[u].Line < 0 ? lastLine : locs[u].Line;
            if (ln == lastLine) continue;
            int bd = 2 * u - lastAddr, ld = ln - lastLine;
            while (bd > 255) { o.Add(255); o.Add(0); bd -= 255; }
            while (ld > 127) { o.Add((byte)bd); o.Add(127); bd = 0; ld -= 127; }
            while (ld < -128) { o.Add((byte)bd); o.Add(unchecked((byte)(sbyte)-128)); bd = 0; ld += 128; }
            o.Add((byte)bd); o.Add(unchecked((byte)(sbyte)ld));
            lastAddr = 2 * u; lastLine = ln;
        }
        return o.ToArray();
    }

    static void Decode310(byte[] tab, int first, Loc[] res)
    {
        int start = 0, line = first;
        for (int i = 0; i + 1 < tab.Length; i += 2)
        {
            int end = start + tab[i];
            int ld = (sbyte)tab[i + 1];
            int ln;
            if (ld == -128) ln = -1; else { line += ld; ln = line; }
            for (int u = start / 2; u < end / 2 && u < res.Length; u++)
                res[u] = ln < 0 ? Loc.None : new Loc(ln, ln, -1, -1);
            start = end;
        }
    }

    static byte[] Encode310(Loc[] locs, int first)
    {
        var o = new List<byte>();
        int prev = first;
        int i = 0;
        while (i < locs.Length)
        {
            int j = i;
            while (j < locs.Length && locs[j].Line == locs[i].Line) j++;
            int remaining = 2 * (j - i);
            int L = locs[i].Line;
            int delta = L < 0 ? 0 : L - prev;
            bool firstChunk = true;
            while (remaining > 0)
            {
                int sd = Math.Min(remaining, 254);
                if (L < 0) { o.Add((byte)sd); o.Add(unchecked((byte)(sbyte)-128)); }
                else
                {
                    int ld = firstChunk ? delta : 0;
                    while (ld > 127) { o.Add(0); o.Add(127); ld -= 127; }
                    while (ld < -127) { o.Add(0); o.Add(unchecked((byte)(sbyte)-127)); ld += 127; }
                    o.Add((byte)sd); o.Add(unchecked((byte)(sbyte)ld));
                }
                remaining -= sd;
                firstChunk = false;
            }
            if (L >= 0) prev = L;
            i = j;
        }
        return o.ToArray();
    }

    static int VarLE(byte[] d, ref int p)
    {
        int b = d[p++];
        int v = b & 63, sh = 0;
        while ((b & 64) != 0) { b = d[p++]; sh += 6; v |= (b & 63) << sh; }
        return v;
    }

    static int SVar(byte[] d, ref int p)
    {
        int v = VarLE(d, ref p);
        return (v & 1) != 0 ? -(v >> 1) : v >> 1;
    }

    static void WrVarLE(List<byte> o, int v)
    {
        while (v >= 64) { o.Add((byte)(64 | (v & 63))); v >>= 6; }
        o.Add((byte)v);
    }

    static void WrSVar(List<byte> o, int v) => WrVarLE(o, v < 0 ? ((-v) << 1) | 1 : v << 1);

    static void DecodeLocation(byte[] tab, int first, Loc[] res)
    {
        int p = 0, line = first, u = 0;
        while (p < tab.Length)
        {
            int b = tab[p++];
            int code = (b >> 3) & 15;
            int n = (b & 7) + 1;
            Loc loc;
            if (code == 15) loc = Loc.None;
            else if (code == 14)
            {
                line += SVar(tab, ref p);
                int el = VarLE(tab, ref p);
                int c = VarLE(tab, ref p);
                int ec = VarLE(tab, ref p);
                loc = new Loc(line, line + el, c - 1, ec - 1);
            }
            else if (code == 13)
            {
                line += SVar(tab, ref p);
                loc = new Loc(line, line, -1, -1);
            }
            else if (code >= 10)
            {
                line += code - 10;
                int c = tab[p++], ec = tab[p++];
                loc = new Loc(line, line, c, ec);
            }
            else
            {
                int s = tab[p++];
                int c = (code << 3) | (s >> 4);
                loc = new Loc(line, line, c, c + (s & 15));
            }
            for (int k = 0; k < n && u < res.Length; k++) res[u++] = loc;
        }
    }

    static byte[] EncodeLocation(Loc[] locs, int first)
    {
        var o = new List<byte>();
        int prev = first, i = 0;
        while (i < locs.Length)
        {
            int j = i;
            while (j < locs.Length && locs[j] == locs[i] && j - i < 8) j++;
            int n = j - i;
            var l = locs[i];
            int Hdr(int code) => 0x80 | (code << 3) | (n - 1);

            if (l.Line < 0) o.Add((byte)Hdr(15));
            else if (l.Col < 0)
            {
                o.Add((byte)Hdr(13)); WrSVar(o, l.Line - prev); prev = l.Line;
            }
            else if (l.EndLine == l.Line && l.Line == prev && l.Col < 80 && l.EndCol - l.Col >= 0 && l.EndCol - l.Col <= 15)
            {
                o.Add((byte)Hdr(l.Col >> 3)); o.Add((byte)(((l.Col & 7) << 4) | (l.EndCol - l.Col)));
            }
            else if (l.EndLine == l.Line && l.Line - prev >= 0 && l.Line - prev <= 2 && l.Col < 256 && l.EndCol >= 0 && l.EndCol < 256)
            {
                o.Add((byte)Hdr(10 + l.Line - prev)); o.Add((byte)l.Col); o.Add((byte)l.EndCol); prev = l.Line;
            }
            else
            {
                o.Add((byte)Hdr(14));
                WrSVar(o, l.Line - prev);
                WrVarLE(o, l.EndLine - l.Line);
                WrVarLE(o, l.Col + 1);
                WrVarLE(o, l.EndCol + 1);
                prev = l.Line;
            }
            i = j;
        }
        return o.ToArray();
    }

    static int VarBE(byte[] d, ref int p)
    {
        int b = d[p++];
        int v = b & 63;
        while ((b & 64) != 0) { v <<= 6; b = d[p++]; v |= b & 63; }
        return v;
    }

    static void WrVarBE(List<byte> o, int v, bool first)
    {
        var g = new List<int>();
        do { g.Add(v & 63); v >>= 6; } while (v != 0);
        g.Reverse();
        for (int i = 0; i < g.Count; i++)
        {
            int b = g[i] | (i < g.Count - 1 ? 64 : 0);
            if (i == 0 && first) b |= 0x80;
            o.Add((byte)b);
        }
    }

    public static List<ExcEntry> DecodeExc(byte[] tab)
    {
        var res = new List<ExcEntry>();
        int p = 0;
        try
        {
            while (p < tab.Length)
            {
                int s = VarBE(tab, ref p), len = VarBE(tab, ref p), t = VarBE(tab, ref p), dl = VarBE(tab, ref p);
                res.Add(new ExcEntry(s, checked(s + len), t, dl >> 1, (dl & 1) != 0));
            }
        }
        catch (IndexOutOfRangeException)
        {
            throw new PycFormatException("Malformed co_exceptiontable: truncated varint sequence.");
        }
        catch (OverflowException)
        {
            throw new PycFormatException("Malformed co_exceptiontable: offset overflow.");
        }
        return res;
    }

    public static byte[] EncodeExc(IEnumerable<ExcEntry> entries)
    {
        var o = new List<byte>();
        foreach (var e in entries)
        {
            WrVarBE(o, e.Start, true);
            WrVarBE(o, e.End - e.Start, false);
            WrVarBE(o, e.Target, false);
            WrVarBE(o, (e.Depth << 1) | (e.LastI ? 1 : 0), false);
        }
        return o.ToArray();
    }
}
