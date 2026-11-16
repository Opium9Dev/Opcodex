namespace Opcodex.Pyc;

public static class StackSimulator
{
    sealed record Handler(int Start, int End, int Target, int Depth, bool LastI);

    sealed class BlockState
    {
        public StackBlock Block;
        public int EndIndex;
        public int? EntryDepth;
        public List<int> Successors = new();
        public int PredecessorCount;
    }

    static readonly HashSet<string> Unconditional = new(StringComparer.Ordinal)
    {
        "JUMP_FORWARD", "JUMP_BACKWARD", "JUMP_BACKWARD_NO_INTERRUPT", "JUMP_ABSOLUTE", "JUMP",
    };

    static readonly HashSet<string> Terminal = new(StringComparer.Ordinal)
    {
        "RETURN_VALUE", "RETURN_CONST", "RAISE_VARARGS", "RERAISE",
    };

    static readonly string[] CommonConstants =
    {
        "AssertionError", "NotImplementedError", "tuple", "all", "any",
        "list", "set", "None", "''", "True", "False", "-1", "frozenset", "()",
    };

    static readonly string[] SpecialNames = { "__enter__", "__exit__", "__aenter__", "__aexit__" };

    public static StackSimulationResult Analyze(PyCode code, OpcodeTable opcodes)
    {
        ArgumentNullException.ThrowIfNull(code);
        ArgumentNullException.ThrowIfNull(opcodes);
        var result = new StackSimulationResult { DeclaredStackSize = code.StackSize };
        if (!StackEffectModel.IsModeled(opcodes.Minor))
        {
            result.Diagnostics.Add(new("error", "UNSUPPORTED_STACK_MODEL", -1,
                $"Python 3.{opcodes.Minor} has no verified stack-effect model."));
            return result;
        }
        if (opcodes.Minor < 12)
            result.Diagnostics.Add(new("info", "VERSION_UNVERIFIED", -1,
                $"The Python 3.{opcodes.Minor} stack model is implemented but has not been validated against a CPython corpus."));

        var decoded = Disassembler.Disassemble(code, opcodes);
        var instructions = new List<Instruction>();
        var offsetToIndex = new Dictionary<int, int>();
        int nextIndex = 0;
        foreach (var ins in decoded)
        {
            offsetToIndex[ins.Offset] = nextIndex;
            if (ins.Name is "EXTENDED_ARG" or "CACHE") continue;
            instructions.Add(ins);
            nextIndex++;
        }
        if (instructions.Count == 0) return result;

        var handlers = ReadHandlers(code, opcodes, result.Diagnostics);
        var leaders = new SortedSet<int> { 0 };
        int codeLength = code.Code.Data.Length;
        for (int k = 0; k < instructions.Count; k++)
        {
            var ins = instructions[k];
            bool hasJump = ins.Target.HasValue && ins.Name != "END_ASYNC_FOR";
            if (hasJump)
            {
                if (offsetToIndex.TryGetValue(ins.Target.Value, out int target)) leaders.Add(target);
                else result.Diagnostics.Add(new("error", "BAD_JUMP_TARGET", ins.Offset,
                    $"Target 0x{ins.Target.Value:x} is not an instruction boundary."));
            }
            if ((hasJump || Terminal.Contains(ins.Name)) && k + 1 < instructions.Count)
                leaders.Add(k + 1);
        }
        foreach (var handler in handlers)
        {
            AddExceptionBoundary(handler.Start, handler, offsetToIndex, instructions.Count, codeLength, leaders, result.Diagnostics);
            AddExceptionBoundary(handler.End, handler, offsetToIndex, instructions.Count, codeLength, leaders, result.Diagnostics);
            if (offsetToIndex.TryGetValue(handler.Target, out int target)) leaders.Add(target);
            else result.Diagnostics.Add(new("error", "BAD_EXCEPTION_TARGET", handler.Target,
                "Exception handler target is not an instruction boundary."));
        }

        var leaderList = leaders.Where(i => i >= 0 && i < instructions.Count).ToList();
        var states = new List<BlockState>(leaderList.Count);
        for (int i = 0; i < leaderList.Count; i++)
        {
            var block = new StackBlock { Id = i, StartOffset = instructions[leaderList[i]].Offset };
            int end = i + 1 < leaderList.Count ? leaderList[i + 1] : instructions.Count;
            for (int k = leaderList[i]; k < end; k++) block.Instructions.Add(instructions[k]);
            result.Blocks.Add(block);
            states.Add(new BlockState { Block = block, EndIndex = end });
        }

        var blockAtIndex = leaderList.Select((index, id) => (index, id)).ToDictionary(x => x.index, x => x.id);
        int? TargetBlock(Instruction ins)
        {
            if (ins.Target is int target && ins.Name != "END_ASYNC_FOR" &&
                offsetToIndex.TryGetValue(target, out int index) && blockAtIndex.TryGetValue(index, out int id))
                return id;
            return null;
        }

        for (int i = 0; i < states.Count; i++)
        {
            var last = states[i].Block.Instructions[^1];
            int? target = TargetBlock(last);
            bool conditional = IsConditional(last.Name);
            if (target.HasValue && !states[i].Successors.Contains(target.Value))
            {
                states[i].Successors.Add(target.Value);
                states[target.Value].PredecessorCount++;
                AddEdge(result, i, target.Value,
                    conditional ? StackEdgeKind.BranchTaken : StackEdgeKind.Jump, last.Offset);
                if (conditional) states[i].Block.BranchTargetBlock = target.Value;
            }
            bool falls = !Unconditional.Contains(last.Name) && !Terminal.Contains(last.Name);
            if (conditional && !target.HasValue) falls = false;
            if (falls && i + 1 < states.Count && !states[i].Successors.Contains(i + 1))
            {
                states[i].Successors.Add(i + 1);
                states[i + 1].PredecessorCount++;
                AddEdge(result, i, i + 1,
                    conditional ? StackEdgeKind.BranchFallThrough : StackEdgeKind.FallThrough, last.Offset);
            }
        }
        AddExceptionEdges(result, states, handlers);

        var work = new Queue<int>();
        void SetEntry(int blockId, IReadOnlyList<StackExpr> incoming, int offset, string cause, int? fromBlock = null)
        {
            var state = states[blockId];
            state.Block.EntryStates.Add(new StackIncomingState(fromBlock, cause, offset, incoming.ToList()));
            if (state.EntryDepth is int depth)
            {
                if (depth != incoming.Count)
                    result.Diagnostics.Add(new("error", "STACK_DEPTH_MISMATCH", offset,
                        $"Block B{blockId} entered with depth {incoming.Count}; expected {depth} ({cause})."));
                return;
            }
            state.EntryDepth = incoming.Count;
            state.Block.Reachable = true;
            if (state.PredecessorCount > 1 && blockId != 0)
            {
                for (int slot = 0; slot < incoming.Count; slot++)
                    state.Block.EntryStack.Add(StackExpr.Phi(blockId, slot));
            }
            else state.Block.EntryStack.AddRange(incoming);
            work.Enqueue(blockId);
        }

        SetEntry(0, Array.Empty<StackExpr>(), 0, "entry");
        foreach (var handler in handlers)
        {
            if (!offsetToIndex.TryGetValue(handler.Target, out int index) ||
                !blockAtIndex.TryGetValue(index, out int blockId)) continue;
            var handlerStack = new List<StackExpr>();
            for (int slot = 0; slot < handler.Depth; slot++)
                handlerStack.Add(StackExpr.HandlerSlot(blockId, slot, "inherited"));
            if (handler.LastI) handlerStack.Add(StackExpr.HandlerSlot(blockId, handler.Depth, "lasti"));
            handlerStack.Add(StackExpr.HandlerSlot(blockId, handler.Depth + (handler.LastI ? 1 : 0), "exception"));
            SetEntry(blockId, handlerStack, handler.Target, $"exception handler depth={handler.Depth}");
        }

        var processed = new HashSet<int>();
        while (work.Count > 0)
        {
            int blockId = work.Dequeue();
            if (!processed.Add(blockId)) continue;
            SimulateBlock(code, opcodes, result, states, blockAtIndex, offsetToIndex, handlers, SetEntry, blockId);
        }

        foreach (var block in result.Blocks)
            for (int slot = 0; slot < block.EntryStack.Count; slot++)
                if (block.EntryStack[slot].Kind == StackExprKind.Phi)
                    result.Phis.Add(new StackPhi(block.Id, slot, block.EntryStates
                        .Where(state => state.Values.Count > slot)
                        .Select(state => new StackPhiInput(state.FromBlock, state.Cause, state.Values[slot]))
                        .ToList()));

        for (int i = 0; i < result.Blocks.Count; i++)
            if (!result.Blocks[i].Reachable)
                result.Diagnostics.Add(new("info", "UNREACHABLE", result.Blocks[i].StartOffset, $"Block B{i} is unreachable."));
        if (result.MaxDepth > code.StackSize)
            result.Diagnostics.Add(new("error", "STACKSIZE_EXCEEDED", -1,
                $"Simulated stack depth {result.MaxDepth} exceeds co_stacksize {code.StackSize}."));
        StackControlFlowAnalyzer.Analyze(result);
        return result;
    }

    static void AddExceptionBoundary(int offset, Handler handler, Dictionary<int, int> offsetToIndex,
        int instructionCount, int codeLength, SortedSet<int> leaders, List<StackDiagnostic> diagnostics)
    {
        if (offset == codeLength) return;
        if (offsetToIndex.TryGetValue(offset, out int index) && index < instructionCount)
        {
            leaders.Add(index);
            return;
        }
        diagnostics.Add(new("error", "BAD_EXCEPTION_BOUNDARY", offset,
            $"Exception range [{handler.Start}, {handler.End}) is not aligned to an instruction boundary."));
    }

    static void AddEdge(StackSimulationResult result, int from, int to, StackEdgeKind kind, int sourceOffset)
    {
        if (result.Edges.Any(e => e.FromBlock == from && e.ToBlock == to && e.Kind == kind &&
            e.ExceptionDepth == null))
            return;
        var edge = new StackEdge(from, to, kind, sourceOffset);
        result.Edges.Add(edge);
        result.Blocks[from].Successors.Add(edge);
        result.Blocks[to].Predecessors.Add(edge);
    }

    static void AddExceptionEdges(StackSimulationResult result, List<BlockState> states, List<Handler> handlers)
    {
        foreach (var handler in handlers)
        {
            int targetBlock = states.FindIndex(s => s.Block.StartOffset == handler.Target);
            if (targetBlock < 0) continue;
            foreach (var state in states)
            {
                var protectedInstruction = state.Block.Instructions.FirstOrDefault(i =>
                    handler.Start <= i.Offset && i.Offset < handler.End);
                if (protectedInstruction == null) continue;
                var edge = new StackEdge(state.Block.Id, targetBlock, StackEdgeKind.Exception,
                    protectedInstruction.Offset, handler.Depth, handler.LastI);
                result.Edges.Add(edge);
                state.Block.Successors.Add(edge);
                states[targetBlock].Block.Predecessors.Add(edge);
            }
        }
    }

    static bool IsConditional(string name) =>
        name.StartsWith("POP_JUMP_", StringComparison.Ordinal) ||
        name is "JUMP_IF_TRUE_OR_POP" or "JUMP_IF_FALSE_OR_POP" or "JUMP_IF_NOT_EXC_MATCH" or
            "FOR_ITER" or "SEND" or "SETUP_FINALLY" or "SETUP_WITH" or "SETUP_ASYNC_WITH" or "CALL_FINALLY";

    static List<Handler> ReadHandlers(PyCode code, OpcodeTable opcodes, List<StackDiagnostic> diagnostics)
    {
        var handlers = new List<Handler>();
        if (opcodes.Minor < 11 || code.ExceptionTable.Length == 0) return handlers;
        try
        {
            foreach (var entry in LineTables.DecodeExc(code.ExceptionTable))
            {
                if (entry.Start < 0 || entry.End <= entry.Start || entry.Target < 0 || entry.Depth < 0)
                {
                    diagnostics.Add(new("error", "INVALID_EXCEPTION_ENTRY", entry.Start * 2,
                        $"Invalid exception entry [{entry.Start}, {entry.End}) -> {entry.Target}, depth {entry.Depth}."));
                    continue;
                }
                handlers.Add(new Handler(entry.Start * 2, entry.End * 2, entry.Target * 2, entry.Depth, entry.LastI));
            }
        }
        catch (Exception ex) when (ex is IndexOutOfRangeException or OverflowException or PycFormatException)
        {
            diagnostics.Add(new("error", "INVALID_EXCEPTION_TABLE", -1, ex.Message));
        }
        return handlers;
    }

    static void SimulateBlock(PyCode code, OpcodeTable opcodes, StackSimulationResult result,
        List<BlockState> states, Dictionary<int, int> blockAtIndex, Dictionary<int, int> offsetToIndex,
        List<Handler> handlers, Action<int, IReadOnlyList<StackExpr>, int, string, int?> setEntry, int blockId)
    {
        var block = states[blockId].Block;
        var stack = new List<StackExpr>(block.EntryStack);
        var pendingKeywordNames = (List<string>)null;
        StackExpr Pop(int offset)
        {
            if (stack.Count == 0)
            {
                result.Diagnostics.Add(new("error", "STACK_UNDERFLOW", offset, "Opcode pops from an empty evaluation stack."));
                return StackExpr.Node(StackExprKind.Opaque, "UNDERFLOW");
            }
            var value = stack[^1];
            stack.RemoveAt(stack.Count - 1);
            return value;
        }
        List<StackExpr> PopN(int count, int offset)
        {
            if (count < 0 || count > 100000)
            {
                result.Diagnostics.Add(new("error", "INVALID_STACK_COUNT", offset, $"Invalid pop count {count}."));
                return new List<StackExpr>();
            }
            var values = new StackExpr[count];
            for (int i = count - 1; i >= 0; i--) values[i] = Pop(offset);
            return values.ToList();
        }
        string NameAt(int index, int offset)
        {
            if (index >= 0 && index < code.Names.Length) return code.Names[index];
            result.Diagnostics.Add(new("error", "BAD_NAME_INDEX", offset, $"Name index {index} is out of range."));
            return $"<name #{index}>";
        }
        string LocalAt(int index, string opName, int offset)
        {
            string[] names;
            int resolved = index;
            if (opcodes.Minor >= 11) names = code.LocalsPlusNames ?? Array.Empty<string>();
            else if (opName.Contains("FAST", StringComparison.Ordinal) || opName.Contains("LOCAL", StringComparison.Ordinal))
                names = code.VarNames;
            else
            {
                if (index >= 0 && index < code.CellVars.Length) return code.CellVars[index];
                resolved = index - code.CellVars.Length;
                names = code.FreeVars;
            }
            if (resolved >= 0 && resolved < names.Length) return names[resolved];
            result.Diagnostics.Add(new("error", "BAD_LOCAL_INDEX", offset, $"Local index {index} is out of range for {opName}."));
            return $"<local #{index}>";
        }
        StackExpr NameExpr(Instruction ins, int index = -1)
        {
            int refIndex = index >= 0 ? index : ins.RefIndex;
            return StackExpr.Name(NameAt(refIndex, ins.Offset), ins.Name == "LOAD_NAME" ? "name" : "global");
        }
        StackExpr LocalExpr(Instruction ins, int index = -1, string opName = null)
        {
            int refIndex = index >= 0 ? index : ins.Arg;
            return StackExpr.Name(LocalAt(refIndex, opName ?? ins.Name, ins.Offset),
                (opName ?? ins.Name).Contains("DEREF", StringComparison.Ordinal) ? "deref" : "fast");
        }
        (StackExpr Callable, StackExpr Self) CallableFromFrame(int offset)
        {
            var top = Pop(offset);
            var below = Pop(offset);
            if (top.Kind == StackExprKind.Marker && top.Text is "NULL" or "SELF") return (below, null);
            if (below.Kind == StackExprKind.Marker && below.Text == "NULL") return (top, null);
            return (below, top);
        }
        List<StackExpr> jumpStack = null;
        bool terminated = false;

        foreach (var ins in block.Instructions)
        {
            int before = stack.Count;
            string n = ins.Name;
            int arg = Math.Max(0, ins.Arg);
            if (!StackEffectModel.TryGetEffect(opcodes.Minor, n, arg, out var effect))
            {
                result.Diagnostics.Add(new("error", "UNMODELED_OPCODE", ins.Offset,
                    $"{n} (opcode {ins.Opcode}) has no stack model for Python 3.{opcodes.Minor}."));
                block.Terminator = "analysis stopped";
                return;
            }

            var valuesForOpaque = Array.Empty<StackExpr>();
            bool handled = true;
            switch (n)
            {
                case "NOP": case "RESUME": case "PRECALL": case "MAKE_CELL": case "COPY_FREE_VARS":
                case "NOT_TAKEN": case "SETUP_ANNOTATIONS": case "ENTER_EXECUTOR":
                case "POP_BLOCK": case "EXTENDED_ARG": case "CACHE":
                    break;
                case "KW_NAMES":
                    pendingKeywordNames = ins.RefIndex >= 0 && ins.RefIndex < code.Consts.Count && code.Consts[ins.RefIndex] is PyTuple kt
                        ? kt.Items.Select(x => x is PyStr s ? s.Value : x.Repr()).ToList()
                        : null;
                    break;
                case "PUSH_NULL": stack.Add(StackExpr.Marker("NULL")); break;
                case "LOAD_CONST":
                    if (ins.RefIndex >= 0 && ins.RefIndex < code.Consts.Count) stack.Add(StackExpr.Const(code.Consts[ins.RefIndex]));
                    else
                    {
                        result.Diagnostics.Add(new("error", "BAD_CONST_INDEX", ins.Offset, $"Constant index {ins.RefIndex} is out of range."));
                        stack.Add(StackExpr.Node(StackExprKind.Opaque, "BAD_CONST"));
                    }
                    break;
                case "LOAD_SMALL_INT": stack.Add(StackExpr.Const(new PyInt(ins.Arg))); break;
                case "LOAD_COMMON_CONSTANT":
                    int commonLimit = opcodes.Minor >= 15 ? CommonConstants.Length : 5;
                    stack.Add(StackExpr.Name(arg < commonLimit ? CommonConstants[arg] : $"<common #{arg}>", "builtin"));
                    break;
                case "LOAD_ASSERTION_ERROR": stack.Add(StackExpr.Name("AssertionError", "builtin")); break;
                case "LOAD_BUILD_CLASS": stack.Add(StackExpr.Name("__build_class__", "builtin")); break;
                case "LOAD_NAME": stack.Add(NameExpr(ins)); break;
                case "LOAD_GLOBAL":
                    if (opcodes.Minor >= 11)
                    {
                        var global = StackExpr.Name(NameAt(ins.Arg >> 1, ins.Offset), "global");
                        if ((ins.Arg & 1) != 0)
                        {
                            if (opcodes.Minor >= 13) { stack.Add(global); stack.Add(StackExpr.Marker("NULL")); }
                            else { stack.Add(StackExpr.Marker("NULL")); stack.Add(global); }
                        }
                        else stack.Add(global);
                    }
                    else stack.Add(NameExpr(ins));
                    break;
                case "LOAD_FAST": case "LOAD_FAST_CHECK": case "LOAD_FAST_BORROW":
                    stack.Add(LocalExpr(ins)); break;
                case "LOAD_FAST_AND_CLEAR":
                    stack.Add(StackExpr.Node(StackExprKind.Opaque, n, LocalExpr(ins))); break;
                case "LOAD_FAST_LOAD_FAST": case "LOAD_FAST_BORROW_LOAD_FAST_BORROW":
                    stack.Add(LocalExpr(ins, ins.Arg >> 4, "FAST"));
                    stack.Add(LocalExpr(ins, ins.Arg & 15, "FAST"));
                    break;
                case "LOAD_DEREF": case "LOAD_CLASSDEREF": case "LOAD_CLOSURE":
                    stack.Add(LocalExpr(ins, ins.Arg, "DEREF")); break;
                case "LOAD_FROM_DICT_OR_GLOBALS": case "LOAD_FROM_DICT_OR_DEREF":
                    var mapping = Pop(ins.Offset);
                    stack.Add(StackExpr.Node(StackExprKind.Opaque, n, mapping,
                        n.EndsWith("GLOBALS", StringComparison.Ordinal)
                            ? StackExpr.Name(NameAt(ins.Arg, ins.Offset), "global")
                            : StackExpr.Name(LocalAt(ins.Arg, "DEREF", ins.Offset), "deref")));
                    break;
                case "LOAD_LOCALS": stack.Add(StackExpr.Node(StackExprKind.Opaque, n)); break;
                case "LOAD_ATTR": case "LOAD_METHOD":
                    var receiver = Pop(ins.Offset);
                    int attrIndex = opcodes.Minor >= 12 && n == "LOAD_ATTR" ? ins.Arg >> 1 : ins.RefIndex;
                    var attr = StackExpr.Node(StackExprKind.Attribute, NameAt(attrIndex, ins.Offset), receiver);
                    if (n == "LOAD_METHOD" || (opcodes.Minor >= 12 && (ins.Arg & 1) != 0))
                    {
                        stack.Add(attr);
                        stack.Add(StackExpr.Marker("SELF"));
                    }
                    else stack.Add(attr);
                    break;
                case "LOAD_SUPER_ATTR":
                    var cls = Pop(ins.Offset); var type = Pop(ins.Offset); var globals = Pop(ins.Offset);
                    var super = StackExpr.Node(StackExprKind.Opaque, "super", globals, type, cls);
                    var superAttr = StackExpr.Node(StackExprKind.Attribute, NameAt(ins.Arg >> 2, ins.Offset), super);
                    stack.Add(superAttr);
                    if ((ins.Arg & 1) != 0) stack.Add(StackExpr.Marker("SELF"));
                    break;
                case "LOAD_SPECIAL":
                    var specialReceiver = Pop(ins.Offset);
                    var specialName = arg < SpecialNames.Length ? SpecialNames[arg] : $"<special #{arg}>";
                    stack.Add(StackExpr.Node(StackExprKind.Attribute, specialName, specialReceiver));
                    stack.Add(StackExpr.Marker("SELF"));
                    break;
                case "STORE_NAME": case "STORE_GLOBAL":
                    block.Statements.Add($"{NameAt(ins.RefIndex, ins.Offset)} = {Pop(ins.Offset)}"); break;
                case "STORE_FAST": case "STORE_DEREF":
                    block.Statements.Add($"{LocalAt(ins.Arg, n, ins.Offset)} = {Pop(ins.Offset)}"); break;
                case "STORE_FAST_LOAD_FAST":
                    block.Statements.Add($"{LocalAt(ins.Arg >> 4, "FAST", ins.Offset)} = {Pop(ins.Offset)}");
                    stack.Add(LocalExpr(ins, ins.Arg & 15, "FAST")); break;
                case "STORE_FAST_STORE_FAST":
                    block.Statements.Add($"{LocalAt(ins.Arg >> 4, "FAST", ins.Offset)} = {Pop(ins.Offset)}");
                    block.Statements.Add($"{LocalAt(ins.Arg & 15, "FAST", ins.Offset)} = {Pop(ins.Offset)}");
                    break;
                case "STORE_ATTR":
                    var attrObject = Pop(ins.Offset); var attrValue = Pop(ins.Offset);
                    block.Statements.Add($"{attrObject}.{NameAt(ins.RefIndex, ins.Offset)} = {attrValue}"); break;
                case "STORE_SUBSCR":
                    var subscriptKey = Pop(ins.Offset); var subscriptObject = Pop(ins.Offset); var subscriptValue = Pop(ins.Offset);
                    block.Statements.Add($"{subscriptObject}[{subscriptKey}] = {subscriptValue}"); break;
                case "STORE_SLICE":
                    var sliceHi = Pop(ins.Offset); var sliceLo = Pop(ins.Offset); var sliceObject = Pop(ins.Offset); var sliceValue = Pop(ins.Offset);
                    block.Statements.Add($"{sliceObject}[{sliceLo}:{sliceHi}] = {sliceValue}"); break;
                case "DELETE_NAME": case "DELETE_GLOBAL": block.Statements.Add("del " + NameAt(ins.RefIndex, ins.Offset)); break;
                case "DELETE_FAST": case "DELETE_DEREF": block.Statements.Add("del " + LocalAt(ins.Arg, n, ins.Offset)); break;
                case "DELETE_ATTR": block.Statements.Add("del " + Pop(ins.Offset) + "." + NameAt(ins.RefIndex, ins.Offset)); break;
                case "DELETE_SUBSCR":
                    var deleteKey = Pop(ins.Offset); var deleteObj = Pop(ins.Offset);
                    block.Statements.Add($"del {deleteObj}[{deleteKey}]"); break;
                case "POP_TOP":
                    var popped = Pop(ins.Offset);
                    if (popped.Kind != StackExprKind.Marker) block.Statements.Add(popped.ToString());
                    break;
                case "COPY":
                    if (arg > 0 && stack.Count >= arg) stack.Add(stack[^arg]);
                    else
                    {
                        result.Diagnostics.Add(new("error", "STACK_UNDERFLOW", ins.Offset, $"COPY {arg} exceeds stack depth {stack.Count}."));
                        stack.Add(StackExpr.Node(StackExprKind.Opaque, "UNDERFLOW"));
                    }
                    break;
                case "SWAP":
                    if (arg > 0 && stack.Count >= arg) (stack[^1], stack[^arg]) = (stack[^arg], stack[^1]);
                    else result.Diagnostics.Add(new("error", "STACK_UNDERFLOW", ins.Offset, $"SWAP {arg} exceeds stack depth {stack.Count}."));
                    break;
                case "DUP_TOP":
                    var dup = Pop(ins.Offset); stack.Add(dup); stack.Add(dup); break;
                case "DUP_TOP_TWO":
                    var dupTop = Pop(ins.Offset); var dupBelow = Pop(ins.Offset);
                    stack.Add(dupBelow); stack.Add(dupTop); stack.Add(dupBelow); stack.Add(dupTop); break;
                case "ROT_TWO":
                    var rot2Top = Pop(ins.Offset); var rot2Below = Pop(ins.Offset); stack.Add(rot2Top); stack.Add(rot2Below); break;
                case "ROT_THREE":
                    var rot3Top = Pop(ins.Offset); var rot3Middle = Pop(ins.Offset); var rot3Bottom = Pop(ins.Offset);
                    stack.Add(rot3Top); stack.Add(rot3Bottom); stack.Add(rot3Middle); break;
                case "ROT_FOUR":
                    var rot4Top = Pop(ins.Offset); var rot4a = Pop(ins.Offset); var rot4b = Pop(ins.Offset); var rot4Bottom = Pop(ins.Offset);
                    stack.Add(rot4Top); stack.Add(rot4Bottom); stack.Add(rot4b); stack.Add(rot4a); break;
                case "ROT_N":
                    if (arg > 0 && stack.Count >= arg)
                    {
                        var value = stack[^1];
                        stack.RemoveAt(stack.Count - 1);
                        stack.Insert(stack.Count - arg + 1, value);
                    }
                    else result.Diagnostics.Add(new("error", "STACK_UNDERFLOW", ins.Offset, $"ROT_N {arg} exceeds stack depth {stack.Count}."));
                    break;
                case "BINARY_OP":
                    var right = Pop(ins.Offset); var left = Pop(ins.Offset);
                    string op = arg < opcodes.NbOps.Length ? opcodes.NbOps[arg] : "?";
                    stack.Add(op == "[]" ? StackExpr.Node(StackExprKind.Subscript, null, left, right)
                        : StackExpr.Node(StackExprKind.Binary, op, left, right));
                    break;
                case "BINARY_SUBSCR":
                    var index = Pop(ins.Offset); var indexed = Pop(ins.Offset);
                    stack.Add(StackExpr.Node(StackExprKind.Subscript, null, indexed, index)); break;
                case "BINARY_SLICE":
                    var hi = Pop(ins.Offset); var lo = Pop(ins.Offset); var target = Pop(ins.Offset);
                    stack.Add(StackExpr.Node(StackExprKind.Subscript, null, target, StackExpr.Node(StackExprKind.Slice, null, lo, hi))); break;
                case "BUILD_SLICE":
                    var sliceParts = PopN(arg, ins.Offset);
                    stack.Add(StackExpr.Node(StackExprKind.Slice, null, sliceParts.ToArray())); break;
                case "UNARY_NEGATIVE": case "UNARY_POSITIVE": case "UNARY_INVERT": case "UNARY_NOT":
                    var unary = Pop(ins.Offset);
                    stack.Add(StackExpr.Node(StackExprKind.Unary,
                        n == "UNARY_NEGATIVE" ? "-" : n == "UNARY_POSITIVE" ? "+" : n == "UNARY_INVERT" ? "~" : "not ", unary));
                    break;
                case "TO_BOOL":
                    stack.Add(StackExpr.Node(StackExprKind.Opaque, n, Pop(ins.Offset))); break;
                case "COMPARE_OP": case "IS_OP": case "CONTAINS_OP":
                    var compareRight = Pop(ins.Offset); var compareLeft = Pop(ins.Offset);
                    int cmpIndex = opcodes.Minor >= 13 ? arg >> 5 : opcodes.Minor == 12 ? arg >> 4 : arg;
                    string compare = n == "IS_OP" ? (arg != 0 ? "is not" : "is")
                        : n == "CONTAINS_OP" ? (arg != 0 ? "not in" : "in")
                        : cmpIndex >= 0 && cmpIndex < opcodes.Cmp.Length ? opcodes.Cmp[cmpIndex] : "BAD";
                    stack.Add(StackExpr.Node(StackExprKind.Compare, compare, compareLeft, compareRight)); break;
                case "BUILD_TUPLE": case "BUILD_LIST": case "BUILD_SET":
                    var collection = PopN(arg, ins.Offset);
                    stack.Add(StackExpr.Sequence(n == "BUILD_TUPLE" ? StackExprKind.Tuple :
                        n == "BUILD_LIST" ? StackExprKind.List : StackExprKind.Set, collection)); break;
                case "BUILD_MAP":
                    var mapParts = PopN(arg * 2, ins.Offset);
                    stack.Add(StackExpr.Sequence(StackExprKind.Dictionary, mapParts)); break;
                case "BUILD_CONST_KEY_MAP":
                    var keys = Pop(ins.Offset); var mapValues = PopN(arg, ins.Offset);
                    if (keys.Constant is PyTuple tupleKeys && tupleKeys.Items.Count == arg)
                    {
                        var keyValues = new List<StackExpr>();
                        for (int i = 0; i < arg; i++)
                        {
                            keyValues.Add(StackExpr.Const(tupleKeys.Items[i]));
                            keyValues.Add(mapValues[i]);
                        }
                        stack.Add(StackExpr.Sequence(StackExprKind.Dictionary, keyValues));
                    }
                    else
                    {
                        result.Diagnostics.Add(new("error", "BAD_CONST_KEYS", ins.Offset,
                            "BUILD_CONST_KEY_MAP requires a constant key tuple of matching length."));
                        stack.Add(StackExpr.Node(StackExprKind.Opaque, n, new[] { keys }.Concat(mapValues).ToArray()));
                    }
                    break;
                case "LIST_EXTEND": case "SET_UPDATE":
                    var extension = Pop(ins.Offset);
                    int containerDepth = arg;
                    if (containerDepth > 0 && stack.Count >= containerDepth &&
                        stack[^containerDepth].Kind is StackExprKind.List or StackExprKind.Set)
                        stack[^containerDepth].Items.Add(StackExpr.Node(StackExprKind.Starred, null, extension));
                    else result.Diagnostics.Add(new("error", "BAD_CONTAINER", ins.Offset, $"{n} target is not under construction."));
                    break;
                case "DICT_UPDATE": case "DICT_MERGE":
                    var update = Pop(ins.Offset);
                    if (arg > 0 && stack.Count >= arg && stack[^arg].Kind == StackExprKind.Dictionary)
                        stack[^arg].Items.AddRange(new[] { StackExpr.Const(null), update });
                    else result.Diagnostics.Add(new("error", "BAD_CONTAINER", ins.Offset, $"{n} target is not a dictionary under construction."));
                    break;
                case "LIST_APPEND": case "SET_ADD":
                    var added = Pop(ins.Offset);
                    block.Statements.Add($"{n} {StackAt(stack, arg)} <- {added}"); break;
                case "MAP_ADD":
                    var mapValue = Pop(ins.Offset); var mapKey = Pop(ins.Offset);
                    block.Statements.Add($"{n} {StackAt(stack, arg)}[{mapKey}] = {mapValue}"); break;
                case "LIST_TO_TUPLE":
                    var list = Pop(ins.Offset);
                    stack.Add(list.Kind == StackExprKind.List ? StackExpr.Sequence(StackExprKind.Tuple, list.Items)
                        : StackExpr.Node(StackExprKind.Opaque, n, list)); break;
                case "CALL_INTRINSIC_1":
                    var intrinsicArgument = Pop(ins.Offset);
                    string intrinsicName = OpcodeTable.Intrinsic1Name(arg) ?? $"INTRINSIC_1_{arg}";
                    if (intrinsicName == "INTRINSIC_LIST_TO_TUPLE" && intrinsicArgument.Kind == StackExprKind.List)
                        stack.Add(StackExpr.Sequence(StackExprKind.Tuple, intrinsicArgument.Items));
                    else if (intrinsicName == "INTRINSIC_UNARY_POSITIVE")
                        stack.Add(StackExpr.Node(StackExprKind.Unary, "+", intrinsicArgument));
                    else if (intrinsicName == "INTRINSIC_IMPORT_STAR")
                    {
                        string moduleName = intrinsicArgument.Kind == StackExprKind.Import
                            ? intrinsicArgument.Text
                            : StackExprPrinter.TryPrintSource(intrinsicArgument, out string printedModule)
                                ? printedModule
                                : intrinsicArgument.ToString();
                        block.Statements.Add("from " + moduleName + " import *");
                    }
                    else stack.Add(StackExpr.Node(StackExprKind.Opaque, intrinsicName, intrinsicArgument));
                    break;
                case "CALL_INTRINSIC_2":
                    var intrinsicRight = Pop(ins.Offset); var intrinsicLeft = Pop(ins.Offset);
                    stack.Add(StackExpr.Node(StackExprKind.Opaque,
                        OpcodeTable.Intrinsic2Name(arg) ?? $"INTRINSIC_2_{arg}", intrinsicLeft, intrinsicRight));
                    break;
                case "BUILD_STRING":
                    stack.Add(StackExpr.Sequence(StackExprKind.FString, PopN(arg, ins.Offset))); break;
                case "FORMAT_VALUE":
                    var formatSpec = (arg & 4) != 0 ? Pop(ins.Offset) : null;
                    var formattedValue = Pop(ins.Offset);
                    string conversion = (arg & 3) switch { 1 => "!s", 2 => "!r", 3 => "!a", _ => "" };
                    stack.Add(formatSpec == null
                        ? StackExpr.Node(StackExprKind.Formatted, conversion, formattedValue)
                        : StackExpr.Node(StackExprKind.Formatted, conversion, formattedValue, formatSpec));
                    break;
                case "CONVERT_VALUE":
                    var converted = Pop(ins.Offset);
                    stack.Add(StackExpr.Node(StackExprKind.Opaque, "CONVERT_VALUE " + (arg & 3), converted)); break;
                case "FORMAT_SIMPLE":
                    var simpleFormat = Pop(ins.Offset);
                    stack.Add(StackExpr.Node(StackExprKind.Formatted, "", simpleFormat)); break;
                case "FORMAT_WITH_SPEC":
                    var formatWithSpec = Pop(ins.Offset); var formatInput = Pop(ins.Offset);
                    stack.Add(StackExpr.Node(StackExprKind.Formatted, "", formatInput, formatWithSpec)); break;
                case "UNPACK_SEQUENCE":
                    var unpackSource = Pop(ins.Offset);
                    for (int i = arg - 1; i >= 0; i--) stack.Add(StackExpr.Unpack(unpackSource, i, arg));
                    break;
                case "UNPACK_EX":
                    var unpackExSource = Pop(ins.Offset);
                    int beforeStar = arg & 0xFF, afterStar = arg >> 8, unpackCount = beforeStar + afterStar + 1;
                    for (int i = unpackCount - 1; i >= 0; i--)
                        stack.Add(StackExpr.Unpack(unpackExSource, i, unpackCount, beforeStar));
                    break;
                case "CALL": case "CALL_KW": case "CALL_FUNCTION": case "CALL_FUNCTION_KW": case "CALL_METHOD":
                    List<string> keywordNames = null;
                    if (n is "CALL_KW" or "CALL_FUNCTION_KW")
                    {
                        var keywordTuple = Pop(ins.Offset);
                        if (keywordTuple.Constant is PyTuple keywordValues)
                            keywordNames = keywordValues.Items.Select(x => x is PyStr s ? s.Value : x.Repr()).ToList();
                        else result.Diagnostics.Add(new("error", "BAD_KWNAMES", ins.Offset, $"{n} requires a constant keyword-name tuple."));
                    }
                    else if (n == "CALL") { keywordNames = pendingKeywordNames; pendingKeywordNames = null; }
                    var arguments = PopN(arg, ins.Offset);
                    var frame = n is "CALL_FUNCTION" or "CALL_FUNCTION_KW"
                        ? (Callable: Pop(ins.Offset), Self: (StackExpr)null)
                        : CallableFromFrame(ins.Offset);
                    int keywordCount = keywordNames?.Count ?? 0;
                    if (keywordCount > arguments.Count)
                    {
                        result.Diagnostics.Add(new("error", "BAD_KWNAMES", ins.Offset, "More keyword names than call arguments."));
                        keywordCount = 0;
                    }
                    var positional = arguments.Take(arguments.Count - keywordCount).ToList();
                    if (frame.Self != null) positional.Insert(0, frame.Self);
                    var keywords = new List<(string Name, StackExpr Value)>();
                    for (int i = 0; i < keywordCount; i++) keywords.Add((keywordNames[i], arguments[arguments.Count - keywordCount + i]));
                    stack.Add(StackExpr.Call(frame.Callable, positional, keywords));
                    break;
                case "CALL_FUNCTION_EX":
                    var kw = ((arg & 1) != 0 || opcodes.Minor >= 14) ? Pop(ins.Offset) : null;
                    if (kw?.Kind == StackExprKind.Marker && kw.Text == "NULL") kw = null;
                    var callArgs = Pop(ins.Offset);
                    var exFrame = opcodes.Minor <= 10
                        ? (Callable: Pop(ins.Offset), Self: (StackExpr)null)
                        : CallableFromFrame(ins.Offset);
                    var expandedArgs = callArgs.Kind == StackExprKind.Tuple
                        ? callArgs.Items
                        : new List<StackExpr> { StackExpr.Node(StackExprKind.Starred, null, callArgs) };
                    if (exFrame.Self != null) expandedArgs.Insert(0, exFrame.Self);
                    var expandedKeywords = new List<(string Name, StackExpr Value)>();
                    if (kw != null) expandedKeywords.Add((null, kw));
                    stack.Add(StackExpr.Call(exFrame.Callable, expandedArgs, expandedKeywords));
                    break;
                case "MAKE_FUNCTION":
                    if (opcodes.Minor <= 10) Pop(ins.Offset);
                    var codeConstant = Pop(ins.Offset);
                    stack.Add(StackExpr.Node(StackExprKind.Function, (codeConstant.Constant as PyCode)?.Name ?? "?"));
                    if (opcodes.Minor <= 12)
                    {
                        if ((arg & 8) != 0) Pop(ins.Offset);
                        if ((arg & 4) != 0) Pop(ins.Offset);
                        if ((arg & 2) != 0) Pop(ins.Offset);
                        if ((arg & 1) != 0) Pop(ins.Offset);
                    }
                    break;
                case "SET_FUNCTION_ATTRIBUTE":
                    var function = Pop(ins.Offset); var attribute = Pop(ins.Offset);
                    stack.Add(StackExpr.Node(StackExprKind.Opaque, $"SET_FUNCTION_ATTRIBUTE {arg}", attribute, function)); break;
                case "IMPORT_NAME":
                    var fromList = Pop(ins.Offset); var level = Pop(ins.Offset);
                    int levelValue = level.Constant is PyInt pyLevel ? (int)pyLevel.Value : 0;
                    stack.Add(StackExpr.Node(StackExprKind.Import, new string('.', Math.Max(0, levelValue)) + NameAt(ins.RefIndex, ins.Offset), fromList)); break;
                case "IMPORT_FROM":
                    var module = stack.Count > 0 ? stack[^1] : StackExpr.Node(StackExprKind.Opaque, "UNDERFLOW");
                    if (stack.Count == 0) result.Diagnostics.Add(new("error", "STACK_UNDERFLOW", ins.Offset, "IMPORT_FROM requires the module on the stack."));
                    stack.Add(StackExpr.Node(StackExprKind.ImportFrom, NameAt(ins.RefIndex, ins.Offset), module)); break;
                case "IMPORT_STAR":
                    block.Statements.Add("from " + Pop(ins.Offset) + " import *"); break;
                case "YIELD_VALUE": stack.Add(StackExpr.Node(StackExprKind.Yield, null, Pop(ins.Offset))); break;
                case "YIELD_FROM":
                    var sendValue = Pop(ins.Offset); var yieldIterator = Pop(ins.Offset);
                    stack.Add(StackExpr.Node(StackExprKind.YieldFrom, null, yieldIterator, sendValue)); break;
                case "RETURN_VALUE":
                    block.TerminatorExpression = Pop(ins.Offset);
                    block.Terminator = "return " + block.TerminatorExpression;
                    terminated = true; break;
                case "RETURN_CONST":
                    if (ins.RefIndex >= 0 && ins.RefIndex < code.Consts.Count)
                    {
                        block.TerminatorExpression = StackExpr.Const(code.Consts[ins.RefIndex]);
                        block.Terminator = "return " + block.TerminatorExpression;
                    }
                    else result.Diagnostics.Add(new("error", "BAD_CONST_INDEX", ins.Offset, $"Constant index {ins.RefIndex} is out of range."));
                    terminated = true; break;
                case "RAISE_VARARGS":
                    var cause = arg == 2 ? Pop(ins.Offset) : null;
                    var exception = arg >= 1 ? Pop(ins.Offset) : null;
                    block.Terminator = "raise" + (exception == null ? "" : " " + exception) + (cause == null ? "" : " from " + cause);
                    terminated = true; break;
                case "RERAISE": PopN(arg + 1, ins.Offset); block.Terminator = "reraise"; terminated = true; break;
                case "POP_JUMP_IF_FALSE": case "POP_JUMP_FORWARD_IF_FALSE": case "POP_JUMP_BACKWARD_IF_FALSE":
                case "POP_JUMP_IF_TRUE": case "POP_JUMP_FORWARD_IF_TRUE": case "POP_JUMP_BACKWARD_IF_TRUE":
                case "POP_JUMP_IF_NONE": case "POP_JUMP_IF_NOT_NONE": case "POP_JUMP_FORWARD_IF_NONE":
                case "POP_JUMP_FORWARD_IF_NOT_NONE": case "POP_JUMP_BACKWARD_IF_NONE": case "POP_JUMP_BACKWARD_IF_NOT_NONE":
                    var branchValue = Pop(ins.Offset);
                    bool isNoneBranch = n.EndsWith("_IF_NONE", StringComparison.Ordinal);
                    bool isNotNoneBranch = n.EndsWith("_IF_NOT_NONE", StringComparison.Ordinal);
                    block.BranchCondition = isNoneBranch || isNotNoneBranch
                        ? StackExpr.Node(StackExprKind.Compare, isNoneBranch ? "is" : "is not",
                            branchValue, StackExpr.Const(new PyNone()))
                        : branchValue;
                    block.BranchTargetWhenTrue = isNoneBranch || isNotNoneBranch
                        ? true
                        : n.EndsWith("_IF_TRUE", StringComparison.Ordinal);
                    block.Terminator = "branch " + block.BranchCondition;
                    break;
                case "JUMP_IF_FALSE_OR_POP": case "JUMP_IF_TRUE_OR_POP":
                    var boolValue = Pop(ins.Offset);
                    jumpStack = new List<StackExpr>(stack) { boolValue };
                    block.BranchCondition = boolValue;
                    block.BranchTargetWhenTrue = n == "JUMP_IF_TRUE_OR_POP";
                    block.Terminator = "short-circuit " + boolValue;
                    break;
                case "JUMP_IF_NOT_EXC_MATCH":
                    var matchType = Pop(ins.Offset); var matchException = Pop(ins.Offset);
                    block.BranchCondition = StackExpr.Node(StackExprKind.Compare, "exception match", matchException, matchType);
                    block.BranchTargetWhenTrue = false;
                    block.Terminator = "exception-match " + matchException + ", " + matchType;
                    break;
                case "FOR_ITER":
                    var iterator = StackAt(stack, 1);
                    block.BranchCondition = StackExpr.Node(StackExprKind.Opaque, "ITER_HAS_NEXT", iterator);
                    block.BranchTargetWhenTrue = false;
                    block.Terminator = "for-iter " + iterator;
                    jumpStack = new List<StackExpr>(stack);
                    if (opcodes.Minor <= 11 && jumpStack.Count > 0) jumpStack.RemoveAt(jumpStack.Count - 1);
                    else jumpStack.Add(StackExpr.Node(StackExprKind.Opaque, "FOR_ITER_DONE", iterator));
                    if (opcodes.Minor >= 14) jumpStack = new List<StackExpr>(stack) { StackExpr.Node(StackExprKind.Opaque, "FOR_ITER_DONE", iterator) };
                    stack.Add(StackExpr.Node(StackExprKind.Opaque, "FOR_ITER_NEXT", iterator));
                    break;
                case "SEND":
                    var sent = Pop(ins.Offset);
                    var sendReceiver = stack.Count > 0 ? stack[^1] : StackExpr.Node(StackExprKind.Opaque, "UNDERFLOW");
                    var sendResult = StackExpr.Node(StackExprKind.Opaque, "SEND_RESULT", sendReceiver, sent);
                    block.BranchCondition = StackExpr.Node(StackExprKind.Opaque, "SEND_DONE", sendReceiver, sent);
                    block.BranchTargetWhenTrue = true;
                    block.Terminator = "send " + sendReceiver;
                    stack.Add(sendResult);
                    if (opcodes.Minor <= 11)
                    {
                        var senderJump = new List<StackExpr>(stack);
                        while (senderJump.Count > Math.Max(0, stack.Count - 2)) senderJump.RemoveAt(senderJump.Count - 1);
                        senderJump.Add(sendResult);
                        jumpStack = senderJump;
                    }
                    else jumpStack = new List<StackExpr>(stack);
                    break;
                case "SETUP_FINALLY": case "SETUP_WITH": case "SETUP_ASYNC_WITH": case "CALL_FINALLY":
                    var setupBefore = new List<StackExpr>(stack);
                    var setupPopped = PopN(effect.Pops, ins.Offset);
                    for (int i = 0; i < effect.Pushes; i++)
                        stack.Add(StackExpr.Node(StackExprKind.Opaque, n + "_PUSH", setupPopped.Take(1).ToArray()));
                    jumpStack = setupBefore.Take(Math.Max(0, setupBefore.Count - effect.JumpPops))
                        .Concat(Enumerable.Range(0, effect.JumpPushes)
                            .Select(_ => StackExpr.Node(StackExprKind.Opaque, n + "_HANDLER"))).ToList();
                    block.Terminator = "setup handler";
                    break;
                case "END_SEND":
                    var endSendValue = Pop(ins.Offset); Pop(ins.Offset); stack.Add(endSendValue); break;
                case "END_FOR": case "POP_ITER": case "POP_EXCEPT": case "END_ASYNC_FOR":
                    PopN(effect.Pops, ins.Offset); break;
                case "GET_ITER": case "GET_YIELD_FROM_ITER": case "GET_AWAITABLE": case "GET_AITER":
                    var iterValue = Pop(ins.Offset);
                    stack.Add(StackExpr.Node(StackExprKind.Opaque, n, iterValue));
                    break;
                case "GET_ANEXT": case "GET_LEN": case "MATCH_MAPPING": case "MATCH_SEQUENCE":
                    stack.Add(StackExpr.Node(StackExprKind.Opaque, n, StackAt(stack, 1)));
                    break;
                case "MATCH_KEYS":
                    stack.Add(StackExpr.Node(StackExprKind.Opaque, n + "_RESULT")); break;
                case "MATCH_CLASS":
                    var matchNames = Pop(ins.Offset); var matchClass = Pop(ins.Offset); var matchSubject = Pop(ins.Offset);
                    stack.Add(StackExpr.Node(StackExprKind.Opaque, n, matchSubject, matchClass, matchNames)); break;
                case "PUSH_EXC_INFO":
                    var currentException = Pop(ins.Offset);
                    stack.Add(StackExpr.Node(StackExprKind.Opaque, "PREV_EXC"));
                    stack.Add(currentException); break;
                case "CHECK_EXC_MATCH":
                    var checkedType = Pop(ins.Offset);
                    stack.Add(StackExpr.Node(StackExprKind.Compare, "exception match", StackAt(stack, 1), checkedType));
                    break;
                case "CHECK_EG_MATCH":
                    var groupType = Pop(ins.Offset); var groupError = Pop(ins.Offset);
                    stack.Add(StackExpr.Node(StackExprKind.Opaque, "EG_REST", groupError, groupType));
                    stack.Add(StackExpr.Node(StackExprKind.Opaque, "EG_MATCH", groupError, groupType)); break;
                case "BEFORE_WITH": case "BEFORE_ASYNC_WITH":
                    var manager = Pop(ins.Offset);
                    stack.Add(StackExpr.Node(StackExprKind.Opaque, "WITH_EXIT", manager));
                    stack.Add(StackExpr.Node(StackExprKind.Opaque, n + "_ENTER", manager)); break;
                case "WITH_EXCEPT_START":
                    stack.Add(StackExpr.Node(StackExprKind.Opaque, n, stack.TakeLast(4).ToArray())); break;
                case "RETURN_GENERATOR": stack.Add(StackExpr.Node(StackExprKind.Opaque, "SENT_VALUE")); break;
                default:
                    handled = false;
                    break;
            }

            if (!handled)
            {
                valuesForOpaque = PopN(effect.Pops, ins.Offset).ToArray();
                for (int i = 0; i < effect.Pushes; i++)
                    stack.Add(StackExpr.Node(StackExprKind.Opaque, n, valuesForOpaque));
                result.Diagnostics.Add(new("info", "GENERIC_OPCODE", ins.Offset, $"{n}: stack effect modeled; value semantics are opaque."));
            }

            int actualDelta = stack.Count - before;
            int expectedDelta = effect.Pushes - effect.Pops;
            if (actualDelta != expectedDelta && !terminated)
                result.Diagnostics.Add(new("error", "EFFECT_MISMATCH", ins.Offset,
                    $"{n}: simulated fall-through delta {actualDelta:+#;-#;0}, expected {expectedDelta:+#;-#;0}."));
            result.MaxDepth = Math.Max(result.MaxDepth, Math.Max(before, stack.Count));

            foreach (var handler in handlers)
                if (handler.Start <= ins.Offset && ins.Offset < handler.End && before < handler.Depth)
                    result.Diagnostics.Add(new("error", "HANDLER_DEPTH", ins.Offset,
                        $"Stack depth {before} is below protected handler depth {handler.Depth}."));

            if (ins.Target.HasValue && block.Terminator == null)
                block.Terminator = (Unconditional.Contains(n) ? "jump" : "branch") + $" 0x{ins.Target.Value:x}";
            if (terminated) break;
            if (ins.Target.HasValue && n != "END_ASYNC_FOR")
            {
                jumpStack ??= new List<StackExpr>(stack);
                int? jumpBlock = TargetBlock(ins, offsetToIndex, blockAtIndex);
                if (jumpBlock.HasValue) setEntry(jumpBlock.Value, jumpStack, ins.Offset, n, blockId);
                if (!Unconditional.Contains(n))
                {
                    int? fallBlock = blockId + 1 < states.Count ? blockId + 1 : null;
                    if (fallBlock.HasValue) setEntry(fallBlock.Value, stack, ins.Offset, "fall-through", blockId);
                }
                break;
            }
        }

        if (terminated) return;
        if (block.Terminator == null) block.Terminator = "fall-through";
        if (block.Instructions.Count > 0)
        {
            var last = block.Instructions[^1];
            if (!Unconditional.Contains(last.Name) && !Terminal.Contains(last.Name) &&
                blockId + 1 < states.Count && !block.Terminator.StartsWith("branch", StringComparison.Ordinal) &&
                !block.Terminator.StartsWith("short-circuit", StringComparison.Ordinal) &&
                !block.Terminator.StartsWith("for-iter", StringComparison.Ordinal) &&
                !block.Terminator.StartsWith("send", StringComparison.Ordinal) &&
                !block.Terminator.StartsWith("setup", StringComparison.Ordinal))
                setEntry(blockId + 1, stack, last.Offset, "fall-through", blockId);
        }
    }

    static int? TargetBlock(Instruction ins, Dictionary<int, int> offsetToIndex, Dictionary<int, int> blockAtIndex)
    {
        if (ins.Target is int target && ins.Name != "END_ASYNC_FOR" &&
            offsetToIndex.TryGetValue(target, out int index) && blockAtIndex.TryGetValue(index, out int blockId))
            return blockId;
        return null;
    }

    static StackExpr StackAt(List<StackExpr> stack, int depth) =>
        depth > 0 && stack.Count >= depth ? stack[^depth] : StackExpr.Node(StackExprKind.Opaque, "UNDERFLOW");
}
