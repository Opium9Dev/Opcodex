namespace Opcodex.Pyc;

public enum StackExprKind
{
    Name, Constant, Marker, Attribute, Subscript, Slice, Call, Binary, Unary, Compare,
    Tuple, List, Set, Dictionary, Starred, Function, Formatted, FString, Unpack,
    Import, ImportFrom, Yield, YieldFrom, Opaque, Phi, HandlerSlot,
}

public sealed class StackExpr
{
    public StackExprKind Kind { get; }
    public string Text { get; }
    public string Scope { get; }
    public PyObj Constant { get; }
    public List<StackExpr> Items { get; }
    public List<(string Name, StackExpr Value)> Keywords { get; }
    public int Index { get; }
    public int Count { get; }
    public int StarIndex { get; }

    StackExpr(StackExprKind kind, string text = null, string scope = null, PyObj constant = null,
        List<StackExpr> items = null, List<(string Name, StackExpr Value)> keywords = null, int index = -1,
        int count = 0, int starIndex = -1)
    {
        Kind = kind; Text = text; Scope = scope; Constant = constant;
        Items = items ?? new List<StackExpr>(); Keywords = keywords ?? new List<(string, StackExpr)>();
        Index = index; Count = count; StarIndex = starIndex;
    }

    public static StackExpr Name(string name, string scope) => new(StackExprKind.Name, name, scope);
    public static StackExpr Const(PyObj value) => new(StackExprKind.Constant, constant: value);
    public static StackExpr Marker(string kind) => new(StackExprKind.Marker, kind);
    public static StackExpr Node(StackExprKind kind, string text, params StackExpr[] items) =>
        new(kind, text, items: items.ToList());
    public static StackExpr Sequence(StackExprKind kind, IEnumerable<StackExpr> items) =>
        new(kind, items: items.ToList());
    public static StackExpr Call(StackExpr callable, IEnumerable<StackExpr> args,
        IEnumerable<(string Name, StackExpr Value)> keywords)
    {
        var all = new List<StackExpr> { callable };
        all.AddRange(args);
        return new(StackExprKind.Call, items: all, keywords: keywords.ToList());
    }
    public static StackExpr Unpack(StackExpr source, int index, int count, int star = -1) =>
        new(StackExprKind.Unpack, items: new List<StackExpr> { source }, index: index, count: count, starIndex: star);
    public static StackExpr Phi(int block, int slot) => new(StackExprKind.Phi, $"B{block}.{slot}");
    public static StackExpr HandlerSlot(int block, int slot, string kind) => new(StackExprKind.HandlerSlot, $"{kind} B{block}.{slot}");

    public StackExpr CloneWithItems(IEnumerable<StackExpr> items) =>
        new(Kind, Text, Scope, Constant, items.ToList(), Keywords, Index, Count, StarIndex);

    public override string ToString() => StackExprPrinter.FormatDebug(this);
}

public sealed record StackDiagnostic(string Severity, string Code, int Offset, string Message)
{
    public override string ToString() =>
        $"{Severity} {Code}" + (Offset < 0 ? "" : $" @0x{Offset:x}") + $": {Message}";
}

public sealed class StackBlock
{
    public int Id { get; internal set; }
    public int StartOffset { get; internal set; }
    public List<Instruction> Instructions { get; } = new();
    public List<StackExpr> EntryStack { get; } = new();
    public List<StackIncomingState> EntryStates { get; } = new();
    public List<string> Statements { get; } = new();
    public List<StackEdge> Predecessors { get; } = new();
    public List<StackEdge> Successors { get; } = new();
    public HashSet<int> Dominators { get; } = new();
    public HashSet<int> PostDominators { get; } = new();
    public string Terminator { get; internal set; }
    public StackExpr TerminatorExpression { get; internal set; }
    public StackExpr BranchCondition { get; internal set; }
    public bool? BranchTargetWhenTrue { get; internal set; }
    public int? BranchTargetBlock { get; internal set; }
    public int? ImmediateDominator { get; internal set; }
    public int? ImmediatePostDominator { get; internal set; }
    public int? JoinBlockId { get; internal set; }
    public int? LoopHeaderId { get; internal set; }
    public bool Reachable { get; internal set; }
}

public enum StackEdgeKind
{
    FallThrough, Jump, BranchTaken, BranchFallThrough, Exception,
}

public sealed record StackEdge(
    int FromBlock,
    int ToBlock,
    StackEdgeKind Kind,
    int SourceOffset,
    int? ExceptionDepth = null,
    bool LastI = false);

public sealed record StackLoop(int HeaderBlockId, IReadOnlyList<int> Latches, IReadOnlyList<int> Body);

public sealed record StackBranch(
    int BlockId,
    StackExpr Condition,
    int? TrueSuccessor,
    int? FalseSuccessor,
    int? JoinBlockId);

public sealed record StackIncomingState(
    int? FromBlock,
    string Cause,
    int Offset,
    IReadOnlyList<StackExpr> Values);

public sealed record StackPhiInput(int? FromBlock, string Cause, StackExpr Value);

public sealed record StackPhi(int BlockId, int Slot, IReadOnlyList<StackPhiInput> Inputs);

public sealed class StackSimulationResult
{
    public List<StackBlock> Blocks { get; } = new();
    public List<StackEdge> Edges { get; } = new();
    public List<StackLoop> Loops { get; } = new();
    public List<StackBranch> Branches { get; } = new();
    public List<StackPhi> Phis { get; } = new();
    public List<StackDiagnostic> Diagnostics { get; } = new();
    public int MaxDepth { get; internal set; }
    public int DeclaredStackSize { get; internal set; }
    public bool HasErrors => Diagnostics.Any(d => d.Severity == "error");
    public string Dump()
    {
        var lines = new List<string>();
        foreach (var b in Blocks)
        {
            lines.Add($"B{b.Id} @0x{b.StartOffset:x} {(b.Reachable ? "" : "UNREACHABLE")}".TrimEnd());
            if (b.EntryStack.Count != 0) lines.Add("  entry: " + string.Join(", ", b.EntryStack));
            lines.AddRange(b.Statements.Select(s => "  " + s));
            if (b.Terminator != null) lines.Add("  -> " + b.Terminator);
            if (b.BranchCondition != null) lines.Add("  condition: " + b.BranchCondition);
            if (b.ImmediateDominator is int dominator) lines.Add($"  idom: B{dominator}");
            if (b.ImmediatePostDominator is int postDominator) lines.Add($"  ipdom: B{postDominator}");
            if (b.JoinBlockId is int join) lines.Add($"  join: B{join}");
            if (b.LoopHeaderId is int header) lines.Add($"  loop header: B{header}");
            foreach (var edge in b.Successors)
                lines.Add($"  edge: {edge.Kind} -> B{edge.ToBlock}" +
                    (edge.Kind == StackEdgeKind.Exception ? $" (depth {edge.ExceptionDepth}, lasti={edge.LastI})" : ""));
        }
        foreach (var loop in Loops)
            lines.Add($"loop: header B{loop.HeaderBlockId}, latches {string.Join(",", loop.Latches.Select(id => $"B{id}"))}, " +
                $"body {string.Join(",", loop.Body.Select(id => $"B{id}"))}");
        foreach (var phi in Phis)
            lines.Add($"phi B{phi.BlockId}.{phi.Slot} <- " + string.Join(", ",
                phi.Inputs.Select(input => $"{(input.FromBlock is int from ? $"B{from}" : input.Cause)}: {input.Value}")));
        lines.AddRange(Diagnostics.Where(d => d.Severity != "info").Select(d => d.ToString()));
        return string.Join(Environment.NewLine, lines);
    }

    public string ToDot()
    {
        var lines = new List<string>
        {
            "digraph cfg {",
            "  node [shape=box, fontname=\"Consolas\", fontsize=10];",
        };
        foreach (var block in Blocks)
        {
            var label = new List<string> { $"B{block.Id} 0x{block.StartOffset:X}" };
            if (block.EntryStack.Count != 0) label.Add("stack: " + string.Join(", ", block.EntryStack));
            label.AddRange(Phis.Where(phi => phi.BlockId == block.Id)
                .Select(phi => $"phi {phi.Slot}: " + string.Join(", ", phi.Inputs.Select(input => input.Value.ToString()))));
            label.AddRange(block.Statements);
            if (block.BranchCondition != null) label.Add("condition: " + block.BranchCondition);
            if (block.Terminator != null) label.Add(block.Terminator);
            if (!block.Reachable) label.Add("UNREACHABLE");
            string text = string.Join("\\l", label.Select(EscapeDot)) + "\\l";
            lines.Add($"  B{block.Id} [label=\"{text}\"" + (block.LoopHeaderId == block.Id ? ", color=blue, penwidth=2" : "") + "];");
        }

        foreach (var edge in Edges)
        {
            string label = edge.Kind.ToString();
            if (edge.Kind == StackEdgeKind.Exception)
                label += $" depth={edge.ExceptionDepth} lasti={edge.LastI}";
            else if (Branches.FirstOrDefault(b => b.BlockId == edge.FromBlock) is StackBranch branch &&
                branch.Condition != null)
            {
                if (edge.ToBlock == branch.TrueSuccessor) label = "true";
                else if (edge.ToBlock == branch.FalseSuccessor) label = "false";
            }
            lines.Add($"  B{edge.FromBlock} -> B{edge.ToBlock} [label=\"{EscapeDot(label)}\"" +
                (edge.Kind == StackEdgeKind.Exception ? ", style=dashed, color=red" : "") + "];");
        }
        lines.Add("}");
        return string.Join(Environment.NewLine, lines);
    }

    static string EscapeDot(string text) =>
        (text ?? "").Replace("\\", "\\\\").Replace("\"", "\\\"").Replace("\r", "").Replace("\n", "\\n");
}
