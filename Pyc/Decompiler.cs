using System.IO;
using System.Text;
using System.Text.RegularExpressions;

namespace Opcodex.Pyc;

public static class Decompiler
{
    public static StackSimulationResult AnalyzeStack(PyCode co, OpcodeTable t) => AnalyzeControlFlow(co, t);

    public static StackSimulationResult AnalyzeControlFlow(PyCode co, OpcodeTable t) => StackSimulator.Analyze(co, t);

    public static string Decompile(PyCode co, OpcodeTable t)
    {
        try
        {
            var ctx = new DecompCtx(co, t, false);
            var lines = ctx.Run(0);
            return string.Join("\n", lines);
        }
        catch (Exception ex) { return "# decompilation failed: " + ex.Message; }
    }

    public static bool HasIncompleteOutput(string source) =>
        source.Split('\n').Any(line =>
            line.Contains("# incomplete reconstruction:", StringComparison.Ordinal) ||
            line.Contains("# error at ", StringComparison.Ordinal) ||
            line.StartsWith("# decompilation failed:", StringComparison.Ordinal));
}

sealed class FuncInfo
{
    public PyCode Code;
    public Ex Defaults, KwDefaults, Annotations, Annotate;
    public List<string> TypeParameters = new();
    public List<string> Decorators = new();
}

sealed class ClassInfo
{
    public string Name;
    public PyCode Code;
    public List<string> Bases = new(), TypeParameters = new(), Decorators = new();
}
sealed class ExceptCase
{
    public int HeaderOffset, BodyOffset, BodyEndOffset, MismatchOffset;
    public string ExceptionType, Name;
    public bool IsStar;
}
sealed class SimpleTryPlan
{
    public int StartOffset, TryEndOffset, ElseEndOffset, FinallyStartOffset, FinallyEndOffset, FinallyHandlerOffset, HandlerOffset;
    public int FinallyBodyStartIndex, FinallyBodyEndIndex;
    public bool EmitFinallyBodyFromHandler;
    public bool HasElse, HasFinally;
    public List<ExceptCase> Cases = new();
    public HashSet<int> SkippedOffsets = new();
    public HashSet<int> PreservedOffsets = new();
    public HashSet<int> ExplicitContinueOffsets = new();
}
sealed class MatchCasePlan
{
    public string Pattern;
    public string GuardAlias;
    public int GuardStartIndex = -1, GuardEndIndex = -1, BodyStartIndex, BodyEndIndex;
}
sealed class MatchPlan
{
    public int StartIndex, EndIndex;
    public List<MatchCasePlan> Cases = new();
}
sealed class AsyncForPlan
{
    public int StartIndex, BodyStartIndex, EndIndex, EndOffset;
    public string Target, ElementLoadName;
    public HashSet<int> SkippedOffsets = new();
}
sealed class ForState { public int LineIdx; }
sealed class UnpackState { public int N, StarIndex = -1; public string Src; public ForState For; public List<string> Targets = new(); }
sealed class ImportInfo { public string Module; public List<string> Names; }

sealed class DecompileException : Exception
{
    public DecompileException(string message) : base(message) { }
}

sealed class Ex
{
    public string S; public int P = 20;
    public PyObj Const;
    public List<string> Items;
    public List<Ex> CompareOperands;
    public List<string> CompareOperators;
    public List<KeyValuePair<string, string>> Pairs;
    public string Kind = "";
    public FuncInfo Func; public ClassInfo Cls;
    public FuncInfo DecoratedFunc;
    public ClassInfo DecoratedClass;
    public List<string> DecoratorApps;
    public ForState For; public UnpackState Unp; public ImportInfo Imp; public string FromName;
    public string AugL, AugOp, AugR;
    public string Conv = "";
    public string WithManager;
    public bool IsAsync;
    public Ex(string s, int p = 20) { S = s; P = p; }
}

sealed class OpenBlock
{
    public string Kind; public int End, Indent, HeaderIdx, ElseTo = -1, Top;
    public Ex CondEx; public ForState For;
}

sealed class PBool { public int Target; public string Op; public Ex Left; }

sealed class DecompCtx
{
    readonly PyCode co; readonly OpcodeTable t; readonly bool compMode;
    readonly bool annotationMode;
    List<Instruction> ins;
    readonly List<Ex> stack = new();
    readonly List<string> lines = new();
    readonly List<OpenBlock> open = new();
    readonly List<PBool> pend = new();
    List<(int Index, Ex Marker)> iteratorMarkersToRestore;
    readonly List<Ex> inlineCompBuilders = new();
    readonly Dictionary<string, List<string>> compLocalAliases = new(StringComparer.Ordinal);
    int ind;
    List<string> kwnames;
    bool skipPop, afterCopy1;
    bool compBuilder;
    bool suppressWithReturn;
    int tempIndex;
    int skipToOffset = -1;
    int currentOffset;
    public FuncInfo GenericFunctionResult;
    HashSet<int> infiniteLoopEnds = new();
    HashSet<int> loopConditionOffsets = new();
    public string CompElt;
    public Ex AnnotationResult;
    public Dictionary<string, string> ClassAnnotations { get; } = new(StringComparer.Ordinal);

    public DecompCtx(PyCode co, OpcodeTable t, bool compMode, bool annotationMode = false)
    {
        this.co = co;
        this.t = t;
        this.compMode = compMode;
        this.annotationMode = annotationMode;
    }

    static readonly string[] Kw = { "if", "else", "elif", "while", "for", "in", "not", "and", "or", "is", "def", "class", "return", "import", "from",
        "as", "None", "True", "False", "lambda", "yield", "raise", "pass", "break", "continue", "del", "async", "await", "with", "try", "except", "finally" };

    string Sp(int n) => new string(' ', 4 * n);
    void Emit(string s)
    {
        if (!annotationMode) lines.Add(Sp(ind) + s);
    }
    void Push(Ex e) => stack.Add(e);
    Ex Pop()
    {
        if (stack.Count == 0) return new Ex("<?>") { Kind = "underflow" };
        var e = stack[^1]; stack.RemoveAt(stack.Count - 1); return e;
    }
    Ex Peek(int depth = 0) => stack.Count > depth ? stack[^(depth + 1)] : new Ex("<?>") { Kind = "underflow" };
    static string W(Ex e, int minP) => e.P < minP ? "(" + e.S + ")" : e.S;
    static string Strip(string s) => s.Length > 1 && s[0] == '(' && s[^1] == ')' && Balanced(s) ? s.Substring(1, s.Length - 2) : s;
    static bool Balanced(string s)
    {
        int d = 0;
        for (int i = 0; i < s.Length; i++)
        {
            if (s[i] == '(') d++;
            else if (s[i] == ')') { d--; if (d == 0 && i < s.Length - 1) return false; }
        }
        return d == 0;
    }
    static string Operand(Instruction i) => i.Operand.Length >= 2 && i.Operand[0] == '(' ? i.Operand.Substring(1, i.Operand.Length - 2) : i.Operand;
    string NameOf(Instruction i) => i.RefIndex >= 0 && i.RefIndex < co.Names.Length ? co.Names[i.RefIndex] : Operand(i);
    Ex ConstEx(PyObj o)
    {
        var e = new Ex(o == null ? "<null>" : o.Repr()) { Const = o };
        if (o is PyTuple tp) e.Items = tp.Items.Select(x => x.Repr()).ToList();
        if (o is PyCode pc) { e.S = "<code " + pc.Name + ">"; }
        return e;
    }
    Ex Not(Ex e)
    {
        if (e.S.StartsWith("not ") && e.P == 4) return new Ex(e.S.Substring(4), 20);
        return new Ex("not " + W(e, 5), 4);
    }
    int IndexOfOffset(int off) { for (int k = 0; k < ins.Count; k++) if (ins[k].Offset == off) return k; return -1; }

    static int PrecOf(string op) => op switch
    {
        "**" => 13, "*" or "/" or "//" or "%" or "@" => 11, "+" or "-" => 10, "<<" or ">>" => 9, "&" => 8, "^" => 7, "|" => 6, _ => 10
    };

    Ex Bin(string op, Ex a, Ex b)
    {
        if (op == "+" && a.Kind == "fpiece") a = new Ex("f" + PyObj.StrRepr(a.S));
        if (op == "+" && b.Kind == "fpiece") b = new Ex("f" + PyObj.StrRepr(b.S));
        bool aug = op.Length >= 2 && op.EndsWith("=") && op != "==" && op != "!=" && op != "<=" && op != ">=";
        string bare = aug ? op.Substring(0, op.Length - 1) : op;
        int p = PrecOf(bare);
        if (aug)
            return new Ex($"{a.S} {bare} {b.S}", p) { AugL = a.S, AugOp = op, AugR = b.S };
        string l = W(a, bare == "**" ? p + 1 : p), r = W(b, bare == "**" ? p : p + 1);
        return new Ex($"{l} {bare} {r}", p);
    }

    static readonly Dictionary<string, string> OldBin = new()
    {
        ["ADD"] = "+", ["SUBTRACT"] = "-", ["MULTIPLY"] = "*", ["TRUE_DIVIDE"] = "/", ["FLOOR_DIVIDE"] = "//", ["MODULO"] = "%",
        ["POWER"] = "**", ["LSHIFT"] = "<<", ["RSHIFT"] = ">>", ["AND"] = "&", ["OR"] = "|", ["XOR"] = "^", ["MATRIX_MULTIPLY"] = "@",
    };

    public List<string> Run(int baseIndent)
    {
        ind = baseIndent;
        ins = Disassembler.Disassemble(co, t).Where(i => i.Name != "EXTENDED_ARG" && i.Name != "CACHE").ToList();
        var infiniteLoops = BuildInfiniteLoopPlans();
        infiniteLoopEnds = infiniteLoops.Values.ToHashSet();
        loopConditionOffsets = FindLoopConditionOffsets(infiniteLoops.Keys.ToHashSet());
        EmitScopeDeclarations();
        var tryPlans = BuildSimpleTryPlans();
        var matchPlans = BuildMatchPlans();
        var matchesAtIndex = matchPlans.ToDictionary(plan => plan.StartIndex);
        var asyncForPlans = BuildAsyncForPlans();
        var asyncForStarts = asyncForPlans.ToDictionary(plan => plan.StartIndex);
        var asyncForSkippedOffsets = asyncForPlans.SelectMany(plan => plan.SkippedOffsets).ToHashSet();
        var tryStarts = tryPlans.GroupBy(plan => plan.StartOffset)
            .ToDictionary(group => group.Key, group => group.ToList());
        var tryEnds = tryPlans.GroupBy(plan => plan.TryEndOffset)
            .ToDictionary(group => group.Key, group => group.ToList());
        var elseEnds = tryPlans.Where(plan => plan.HasElse).GroupBy(plan => plan.ElseEndOffset)
            .ToDictionary(group => group.Key, group => group.ToList());
        var finallyStarts = tryPlans.Where(plan => plan.HasFinally).GroupBy(plan => plan.FinallyStartOffset)
            .ToDictionary(group => group.Key, group => group.ToList());
        var skippedOffsets = tryPlans.SelectMany(plan => plan.SkippedOffsets).ToHashSet();
        skippedOffsets.UnionWith(BuildCompilerCleanupOffsets());
        skippedOffsets.ExceptWith(tryPlans.SelectMany(plan => plan.PreservedOffsets));
        var explicitContinueOffsets = tryPlans.SelectMany(plan => plan.ExplicitContinueOffsets).ToHashSet();
        int codeLen = co.Code.Data.Length;
        for (int k = 0; k < ins.Count; k++)
        {
            var i = ins[k];
            int off = i.Offset, next = k + 1 < ins.Count ? ins[k + 1].Offset : codeLen;
            currentOffset = off;
            bool inlineFinallyAtOffset = finallyStarts.TryGetValue(off, out var finalPlansAtOffset) &&
                finalPlansAtOffset.Any(plan => plan.EmitFinallyBodyFromHandler);
            if (skipToOffset >= 0 && off < skipToOffset) continue;
            if (off == skipToOffset) skipToOffset = -1;
            if (IsGeneratorEntry(k, i)) continue;
            if (elseEnds.ContainsKey(off) && !inlineFinallyAtOffset) CloseBlocks(off);
            if (tryEnds.TryGetValue(off, out var endingPlans))
            {
                CloseBlocks(off, stopAfterTry: true);
                foreach (var plan in endingPlans)
                {
                    EmitExceptHandlers(plan);
                    if (plan.HasElse)
                    {
                        Emit("else:");
                        open.Add(new OpenBlock { Kind = "else", End = plan.ElseEndOffset, Indent = ind, HeaderIdx = lines.Count - 1 });
                        ind++;
                    }
                }
                if (!inlineFinallyAtOffset) CloseBlocks(off);
            }
            else if (!inlineFinallyAtOffset) CloseBlocks(off);
            if (finallyStarts.TryGetValue(off, out var finallyPlans))
            {
                foreach (var plan in finallyPlans)
                {
                    if (plan.EmitFinallyBodyFromHandler)
                    {
                        Emit("finally:");
                        ind++;
                        int bodyStart = lines.Count;
                        int savedOffset = currentOffset;
                        for (int index = plan.FinallyBodyStartIndex; index < plan.FinallyBodyEndIndex; index++)
                        {
                            currentOffset = ins[index].Offset;
                            int bodyNext = index + 1 < ins.Count ? ins[index + 1].Offset : codeLen;
                            Step(index, ins[index], ins[index].Offset, bodyNext);
                        }
                        if (lines.Count == bodyStart) Emit("pass");
                        ind--;
                        currentOffset = savedOffset;
                        CloseBlocks(off);
                        continue;
                    }
                    int tryIndex = open.FindLastIndex(block => block.Kind == "try");
                    if (tryIndex >= 0 && open.Skip(tryIndex + 1).Any(block => block.Kind == "if"))
                    {
                        Emit("try:");
                        ind++;
                        Emit("pass");
                        ind--;
                    }
                    Emit("finally:");
                    open.Add(new OpenBlock { Kind = "finally", End = plan.FinallyEndOffset, Indent = ind, HeaderIdx = lines.Count - 1 });
                    ind++;
                }
            }
            ResolvePending(off);
            if (matchesAtIndex.TryGetValue(k, out var matchPlan))
            {
                if (stack.Count == 0)
                    Emit("# incomplete reconstruction: match pattern block has no available subject");
                else
                {
                    EmitMatch(matchPlan);
                    k = matchPlan.EndIndex - 1;
                    continue;
                }
            }
            if (explicitContinueOffsets.Contains(off))
            {
                Emit("continue");
                continue;
            }
            if (asyncForStarts.TryGetValue(k, out var asyncForPlan))
            {
                var iterator = Pop();
                Emit($"async for {LocalName(asyncForPlan.Target)} in {Strip(iterator.S)}:");
                open.Add(new OpenBlock
                {
                    Kind = "for",
                    End = asyncForPlan.EndOffset,
                    Indent = ind,
                    HeaderIdx = lines.Count - 1,
                    Top = off,
                });
                ind++;
                if (!compMode && inlineCompBuilders.Count == 0)
                {
                    var activeWithExits = new List<Ex>();
                    for (int index = 0; index < stack.Count; index++)
                    {
                        if (stack[index].Kind == "with_exit")
                            activeWithExits.Add(stack[index]);
                        else if (stack[index].Kind == "with_exit_callable")
                        {
                            activeWithExits.Add(stack[index]);
                            if (index + 1 < stack.Count && stack[index + 1].Kind == "mark")
                                activeWithExits.Add(stack[++index]);
                        }
                    }
                    stack.Clear();
                    stack.AddRange(activeWithExits);
                }
                if (asyncForPlan.ElementLoadName != null)
                    Push(new Ex(LocalName(asyncForPlan.ElementLoadName)));
                k = asyncForPlan.BodyStartIndex - 1;
                continue;
            }
            if (tryStarts.TryGetValue(off, out var starts))
            {
                foreach (var plan in starts)
                {
                    Emit("try:");
                    open.Add(new OpenBlock { Kind = "try", End = plan.TryEndOffset, Indent = ind, HeaderIdx = lines.Count - 1 });
                    ind++;
                }
            }
            if (infiniteLoops.TryGetValue(off, out int loopEnd))
            {
                Emit("while True:");
                open.Add(new OpenBlock
                {
                    Kind = "while",
                    End = loopEnd,
                    Indent = ind,
                    HeaderIdx = lines.Count - 1,
                    Top = off,
                });
                ind++;
            }
            if (skippedOffsets.Contains(off)) continue;
            if (asyncForSkippedOffsets.Contains(off)) continue;
            try { Step(k, i, off, next); }
            catch (DecompileException) { throw; }
            catch (Exception ex) { Emit($"# error at 0x{off:X}: {ex.Message}"); }
        }
        CloseBlocks(int.MaxValue);
        for (int index = 0; index < lines.Count;)
        {
            if (!lines[index].TrimStart().StartsWith("# goto ", StringComparison.Ordinal))
            {
                index++;
                continue;
            }
            int previous = index - 1;
            while (previous >= 0 && string.IsNullOrWhiteSpace(lines[previous])) previous--;
            string priorLine = previous < 0 ? "" : lines[previous].TrimStart();
            if (IsUnconditionalTerminator(priorLine))
                lines.RemoveAt(index);
            else
                index++;
        }
        if (lines.Count == 0) Emit("pass");
        const string incompleteMarker = "# incomplete reconstruction:";
        for (int index = 0; index < lines.Count; index++)
            if ((lines[index].Contains("<?>", StringComparison.Ordinal) ||
                 lines[index].Contains("<unpack>", StringComparison.Ordinal)) &&
                !lines[index].Contains("incomplete reconstruction:", StringComparison.Ordinal))
            {
                string indentation = lines[index].Substring(0, lines[index].Length - lines[index].TrimStart().Length);
                string incomplete = lines[index].TrimStart();
                int markerIndex = incomplete.IndexOf(incompleteMarker, StringComparison.Ordinal);
                string incompleteHeader = markerIndex >= 0
                    ? incomplete.Substring(markerIndex + incompleteMarker.Length).TrimStart()
                    : "";
                string replacement = incomplete.EndsWith(":", StringComparison.Ordinal) &&
                    ((incomplete.StartsWith("pass ", StringComparison.Ordinal) &&
                      incompleteHeader.StartsWith("async for ", StringComparison.Ordinal)) ||
                     incomplete.StartsWith("if ", StringComparison.Ordinal) ||
                     incomplete.StartsWith("while ", StringComparison.Ordinal) ||
                     incomplete.StartsWith("for ", StringComparison.Ordinal))
                    ? "if True:  # incomplete reconstruction: " +
                        (incompleteHeader.StartsWith("async for ", StringComparison.Ordinal) ? incompleteHeader : incomplete)
                    : "pass  # incomplete reconstruction: " + incomplete;
                lines[index] = indentation + replacement;
            }
        for (int index = 0; index < lines.Count; index++)
        {
            string line = lines[index];
            string trimmed = line.TrimStart();
            string indentation = line.Substring(0, line.Length - trimmed.Length);
            if (trimmed.EndsWith(":", StringComparison.Ordinal) &&
                trimmed.StartsWith("pass ", StringComparison.Ordinal) &&
                trimmed.Contains("# incomplete reconstruction: async for ", StringComparison.Ordinal))
            {
                int markerIndex = trimmed.IndexOf(incompleteMarker, StringComparison.Ordinal);
                string header = trimmed.Substring(markerIndex + incompleteMarker.Length).TrimStart();
                lines[index] = indentation + "if True:  # incomplete reconstruction: " + header;
            }
            else if (trimmed == "if :" ||
                trimmed.StartsWith("if ", StringComparison.Ordinal) && trimmed.EndsWith(", :", StringComparison.Ordinal) ||
                trimmed.StartsWith("if ", StringComparison.Ordinal) && trimmed.EndsWith(":", StringComparison.Ordinal) &&
                    trimmed.Substring(3, trimmed.Length - 4).Contains(", ", StringComparison.Ordinal))
            {
                lines[index] = indentation + "if True:  # incomplete reconstruction: " + trimmed;
            }
            else if (trimmed.EndsWith("=", StringComparison.Ordinal) &&
                !trimmed.EndsWith("==", StringComparison.Ordinal) &&
                !trimmed.StartsWith("if ", StringComparison.Ordinal) &&
                !trimmed.StartsWith("while ", StringComparison.Ordinal))
            {
                lines[index] = indentation + "pass  # incomplete reconstruction: " + trimmed;
            }
        }
        for (int index = 0; index < lines.Count; index++)
        {
            string trimmed = lines[index].TrimStart();
            if (!IsSuiteHeader(trimmed)) continue;
            int indentation = lines[index].Length - trimmed.Length;
            int next = index + 1;
            while (next < lines.Count &&
                (string.IsNullOrWhiteSpace(lines[next]) || lines[next].TrimStart().StartsWith("#", StringComparison.Ordinal)))
                next++;
            if (next < lines.Count && lines[next].Length - lines[next].TrimStart().Length > indentation)
                continue;
            lines.Insert(index + 1, Sp(indentation / 4) + "pass  # incomplete reconstruction: empty suite");
        }
        return lines;
    }

    static bool IsSuiteHeader(string line)
    {
        int colon = line.LastIndexOf(':');
        if (colon < 0 || line.Substring(colon + 1).TrimStart() is { Length: > 0 } trailing &&
            !trailing.StartsWith("#", StringComparison.Ordinal))
            return false;
        string header = line.Substring(0, colon);
        return header.StartsWith("if ", StringComparison.Ordinal) ||
            header.StartsWith("elif ", StringComparison.Ordinal) ||
            header is "else" or "try" or "finally" ||
            header.StartsWith("except", StringComparison.Ordinal) ||
            header.StartsWith("for ", StringComparison.Ordinal) ||
            header.StartsWith("async for ", StringComparison.Ordinal) ||
            header.StartsWith("while ", StringComparison.Ordinal) ||
            header.StartsWith("with ", StringComparison.Ordinal) ||
            header.StartsWith("async with ", StringComparison.Ordinal) ||
            header.StartsWith("def ", StringComparison.Ordinal) ||
            header.StartsWith("async def ", StringComparison.Ordinal) ||
            header.StartsWith("class ", StringComparison.Ordinal) ||
            header.StartsWith("match ", StringComparison.Ordinal) ||
            header.StartsWith("case ", StringComparison.Ordinal);
    }

    List<AsyncForPlan> BuildAsyncForPlans()
    {
        var plans = new List<AsyncForPlan>();
        for (int start = 0; start < ins.Count; start++)
        {
            bool startsWithGetAnext = ins[start].Name == "GET_ANEXT";
            if (ins[start].Name != "GET_AITER" && !(compMode && startsWithGetAnext)) continue;
            int getAnext = startsWithGetAnext ? start : -1, endAsyncFor = -1, store = -1, backEdge = -1;
            for (int index = start + 1; index < ins.Count; index++)
            {
                if (getAnext < 0 && ins[index].Name == "GET_ANEXT") getAnext = index;
                if (ins[index].Name == "END_ASYNC_FOR") { endAsyncFor = index; break; }
            }
            if (getAnext < 0 || endAsyncFor < 0) continue;
            for (int index = getAnext + 1; index < endAsyncFor; index++)
            {
                if (store < 0 && ins[index].Name is "STORE_FAST" or "STORE_NAME" or "STORE_DEREF" or
                    "STORE_FAST_STORE_FAST" or "STORE_FAST_LOAD_FAST")
                    store = index;
                if (ins[index].Name is "JUMP_BACKWARD" or "JUMP_BACKWARD_NO_INTERRUPT" or "JUMP_ABSOLUTE" &&
                    ins[index].Target is int target && target <= ins[getAnext].Offset)
                    backEdge = index;
            }
            if (store < 0 || backEdge < store || ins[store].Target is not null) continue;
            string targetName = Operand(ins[store]);
            string elementLoadName = null;
            if (ins[store].Name is "STORE_FAST_STORE_FAST" or "STORE_FAST_LOAD_FAST")
            {
                string[] names = targetName.Split(new[] { ", " }, StringSplitOptions.None);
                targetName = names[0];
                if (ins[store].Name == "STORE_FAST_LOAD_FAST" && names.Length > 1)
                    elementLoadName = names[1];
            }
            int planStart = start;
            if (!startsWithGetAnext &&
                ins.Skip(start + 1).Take(getAnext - start - 1)
                    .Any(instruction => instruction.Name == "LOAD_FAST_AND_CLEAR") &&
                ins.Skip(start + 1).Take(getAnext - start - 1)
                    .Any(instruction => instruction.Name is "BUILD_LIST" or "BUILD_SET" or "BUILD_MAP"))
                planStart = getAnext;
            var plan = new AsyncForPlan
            {
                StartIndex = planStart,
                BodyStartIndex = store + 1,
                EndIndex = endAsyncFor + 1,
                EndOffset = ins[endAsyncFor].Offset,
                Target = targetName,
                ElementLoadName = elementLoadName,
            };
            for (int index = backEdge; index <= endAsyncFor; index++)
                plan.SkippedOffsets.Add(ins[index].Offset);
            plans.Add(plan);
            start = endAsyncFor;
        }
        return plans;
    }

    void EmitExceptHandlers(SimpleTryPlan plan)
    {
        var savedStack = stack.ToList();
        int savedOffset = currentOffset;
        stack.Clear();
        foreach (var exceptionCase in plan.Cases)
        {
            Emit("except" + (exceptionCase.IsStar ? "*" : "") + " " + exceptionCase.ExceptionType +
                (exceptionCase.Name == null ? "" : " as " + exceptionCase.Name) + ":");
            int headerIndex = lines.Count - 1;
            ind++;
            int bodyIndex = IndexOfOffset(exceptionCase.BodyOffset);
            int bodyEndIndex = exceptionCase.BodyEndOffset == co.Code.Data.Length
                ? ins.Count
                : IndexOfOffset(exceptionCase.BodyEndOffset);
            if (bodyIndex < 0 || bodyEndIndex < bodyIndex)
                throw new DecompileException("An exception handler body has an invalid bytecode range.");
            for (int index = bodyIndex; index < bodyEndIndex; index++)
            {
                currentOffset = ins[index].Offset;
                int next = index + 1 < ins.Count ? ins[index + 1].Offset : co.Code.Data.Length;
                Step(index, ins[index], ins[index].Offset, next);
            }
            if (lines.Count - 1 == headerIndex) Emit("pass");
            ind--;
            stack.Clear();
        }
        stack.AddRange(savedStack);
        currentOffset = savedOffset;
    }

    HashSet<int> BuildCompilerCleanupOffsets()
    {
        var skipped = new HashSet<int>();
        if (co.ExceptionTable.Length == 0)
        {
            for (int setupIndex = 0; setupIndex < ins.Count; setupIndex++)
            {
                if (ins[setupIndex].Name is not ("SETUP_WITH" or "SETUP_ASYNC_WITH") ||
                    ins[setupIndex].Target is not int handlerOffset)
                    continue;
                int handlerIndex = IndexOfOffset(handlerOffset);
                if (handlerIndex <= setupIndex) continue;
                bool hasWithHandler = ins.Skip(handlerIndex).Take(24)
                    .TakeWhile(instruction => instruction.Name is not ("JUMP_FORWARD" or "JUMP_BACKWARD"))
                    .Any(instruction => instruction.Name == "WITH_EXCEPT_START");
                if (!hasWithHandler) continue;

                int exitIndex = -1;
                for (int index = setupIndex + 1; index < handlerIndex; index++)
                    if (ins[index].Name == "POP_BLOCK") exitIndex = index;
                if (exitIndex < 0) continue;

                int continuation = -1;
                for (int index = exitIndex + 1; index < handlerIndex; index++)
                {
                    if (ins[index].Name.StartsWith("JUMP", StringComparison.Ordinal) &&
                        ins[index].Target is int target && target > handlerOffset)
                    {
                        continuation = IndexOfOffset(target);
                        break;
                    }
                }
                if (continuation <= handlerIndex) continue;
                for (int index = exitIndex; index < continuation; index++)
                    skipped.Add(ins[index].Offset);
            }
            return skipped;
        }
        var exceptionTargets = LineTables.DecodeExc(co.ExceptionTable)
            .Select(entry => entry.Target * 2)
            .Distinct()
            .ToHashSet();
        if (!StackEffectModel.IsModeled(t.Minor))
        {
            var rawCleanupNames = new HashSet<string>(StringComparer.Ordinal)
            {
                "SWAP", "POP_TOP", "STORE_FAST", "STORE_FAST_STORE_FAST", "STORE_DEREF",
                "DELETE_FAST", "COPY", "POP_EXCEPT", "RERAISE", "CALL_INTRINSIC_1",
                "CLEANUP_THROW", "NOT_TAKEN",
            };
            foreach (int target in exceptionTargets)
            {
                int start = IndexOfOffset(target);
                if (start < 0) continue;
                bool withHandler = ins.Skip(start).Take(24)
                    .TakeWhile(instruction => instruction.Name is not ("JUMP_FORWARD" or "JUMP_BACKWARD"))
                    .Any(instruction => instruction.Name == "WITH_EXCEPT_START");
                if (withHandler)
                {
                    bool sawReraise = false;
                    for (int index = start; index < ins.Count && index - start < 64; index++)
                    {
                        skipped.Add(ins[index].Offset);
                        if (ins[index].Name == "RERAISE") sawReraise = true;
                        if (sawReraise && ins[index].Name == "JUMP_FORWARD" &&
                            ins[index].Target is int continuation && continuation > ins[index].Offset)
                            break;
                    }
                    continue;
                }

                if (ins[start].Name == "PUSH_EXC_INFO") continue;
                bool validCleanup = true, foundReraise = false;
                var cleanup = new List<int>();
                for (int index = start; index < ins.Count && index - start < 16; index++)
                {
                    string name = ins[index].Name;
                    if (!rawCleanupNames.Contains(name))
                    {
                        validCleanup = false;
                        break;
                    }
                    cleanup.Add(ins[index].Offset);
                    if (name == "RERAISE")
                    {
                        foundReraise = true;
                        break;
                    }
                }
                if (validCleanup && foundReraise)
                    skipped.UnionWith(cleanup);
            }
            return skipped;
        }
        for (int index = 0; index + 2 < ins.Count; index++)
        {
            if (ins[index].Name != "END_FOR" || ins[index + 1].Name != "POP_TOP") continue;
            int builderIndex = -1;
            for (int cursor = index - 1; cursor >= 0; cursor--)
            {
                if (ins[cursor].Name is "BUILD_LIST" or "BUILD_SET" or "BUILD_MAP")
                {
                    builderIndex = cursor;
                    break;
                }
            }
            if (builderIndex < 0) continue;
            var clearedLocals = ins.Skip(Math.Max(0, builderIndex - 8))
                .Take(builderIndex - Math.Max(0, builderIndex - 8))
                .Where(instruction => instruction.Name == "LOAD_FAST_AND_CLEAR")
                .Select(instruction => Operand(instruction))
                .ToHashSet(StringComparer.Ordinal);
            if (clearedLocals.Count == 0) continue;
            bool restoresComprehensionLocal = false;
            for (int cursor = index + 2; cursor < ins.Count &&
                 ins[cursor].Name is "STORE_FAST" or "STORE_NAME" or "STORE_DEREF" or
                     "STORE_FAST_STORE_FAST" or "STORE_FAST_LOAD_FAST"; cursor++)
            {
                if (Operand(ins[cursor]).Split(new[] { ", " }, StringSplitOptions.None)
                    .Any(clearedLocals.Contains))
                {
                    restoresComprehensionLocal = true;
                    break;
                }
            }
            if (restoresComprehensionLocal) skipped.Add(ins[index + 1].Offset);
        }
        var analysis = StackSimulator.Analyze(co, t);
        if (analysis.Blocks.Count == 0) return skipped;

        var normalReachable = new HashSet<int> { 0 };
        var normalWork = new Queue<int>();
        normalWork.Enqueue(0);
        while (normalWork.Count > 0)
        {
            int current = normalWork.Dequeue();
            foreach (var edge in analysis.Blocks[current].Successors)
                if (edge.Kind != StackEdgeKind.Exception && normalReachable.Add(edge.ToBlock))
                    normalWork.Enqueue(edge.ToBlock);
        }
        var indexByOffset = ins.Select((instruction, index) => (instruction.Offset, index))
            .ToDictionary(item => item.Offset, item => item.index);
        var asyncForExits = LineTables.DecodeExc(co.ExceptionTable)
            .Select(entry => (
                Start: entry.Start * 2,
                End: entry.End * 2,
                Target: entry.Target * 2))
            .Where(entry => indexByOffset.TryGetValue(entry.Target, out int targetIndex) &&
                ins[targetIndex].Name == "END_ASYNC_FOR")
            .ToArray();
        var normalInstructions = new HashSet<int>();
        var instructionWork = new Queue<int>();
        if (ins.Count > 0) instructionWork.Enqueue(0);
        while (instructionWork.Count > 0)
        {
            int index = instructionWork.Dequeue();
            if (index < 0 || index >= ins.Count || !normalInstructions.Add(index)) continue;
            var instruction = ins[index];
            string name = instruction.Name;
            bool terminal = name is "RETURN_VALUE" or "RETURN_CONST" or "RAISE_VARARGS" or "RERAISE";
            bool conditional = name.StartsWith("POP_JUMP", StringComparison.Ordinal) ||
                name.StartsWith("JUMP_IF", StringComparison.Ordinal) ||
                name is "FOR_ITER" or "SEND";
            if (instruction.Target is int target && indexByOffset.TryGetValue(target, out int targetIndex))
                instructionWork.Enqueue(targetIndex);
            if (name == "GET_ANEXT")
                foreach (var exit in asyncForExits)
                    if (instruction.Offset >= exit.Start && instruction.Offset < exit.End &&
                        indexByOffset.TryGetValue(exit.Target, out int exitIndex))
                        instructionWork.Enqueue(exitIndex);
            if (!terminal && (conditional || !name.StartsWith("JUMP", StringComparison.Ordinal)) &&
                index + 1 < ins.Count)
                instructionWork.Enqueue(index + 1);
        }
        foreach (var block in analysis.Blocks)
            if (block.Instructions.Any(instruction =>
                    indexByOffset.TryGetValue(instruction.Offset, out int index) && normalInstructions.Contains(index)))
                normalReachable.Add(block.Id);

        var handlerOffsets = exceptionTargets;
        var withHandlers = handlerOffsets
            .Where(offset => analysis.Blocks.Any(block => block.StartOffset == offset &&
                block.Instructions.Any(instruction => instruction.Name == "WITH_EXCEPT_START")))
            .Select(offset => analysis.Blocks.First(block => block.StartOffset == offset).Id)
            .ToHashSet();
        var cleanupNames = new HashSet<string>(StringComparer.Ordinal)
        {
            "SWAP", "POP_TOP", "STORE_FAST", "STORE_FAST_STORE_FAST", "STORE_DEREF",
            "DELETE_FAST", "COPY", "POP_EXCEPT", "PUSH_EXC_INFO", "RERAISE", "NOT_TAKEN", "NOP",
        };
        bool IsCleanupBlock(StackBlock block) =>
            block.Instructions.Count > 0 && block.Instructions.All(instruction => cleanupNames.Contains(instruction.Name));

        var work = new Queue<(int BlockId, bool WithHandlerRegion)>();
        foreach (int blockId in withHandlers) work.Enqueue((blockId, true));
        var visited = new HashSet<(int BlockId, bool WithHandlerRegion)>();
        foreach (var block in analysis.Blocks.Where(block =>
                     handlerOffsets.Contains(block.StartOffset) &&
                     !normalReachable.Contains(block.Id) && IsCleanupBlock(block)))
            work.Enqueue((block.Id, false));

        while (work.Count > 0)
        {
            var (current, withHandlerRegion) = work.Dequeue();
            if (!visited.Add((current, withHandlerRegion)) || normalReachable.Contains(current)) continue;
            var block = analysis.Blocks[current];
            foreach (var instruction in block.Instructions) skipped.Add(instruction.Offset);
            foreach (var edge in block.Successors)
                if (!normalReachable.Contains(edge.ToBlock) &&
                    (withHandlerRegion || edge.Kind == StackEdgeKind.Exception ||
                     IsCleanupBlock(analysis.Blocks[edge.ToBlock])))
                    work.Enqueue((edge.ToBlock, withHandlerRegion));
        }
        return skipped;
    }

    bool IsGeneratorEntry(int index, Instruction instruction) =>
        instruction.Name == "POP_TOP" && index > 0 && ins[index - 1].Name == "RETURN_GENERATOR";

    HashSet<int> FindLoopConditionOffsets(HashSet<int> infiniteLoopHeaders)
    {
        var offsets = new HashSet<int>();
        if (!StackEffectModel.IsModeled(t.Minor)) return offsets;
        var analysis = StackSimulator.Analyze(co, t);
        foreach (var loop in analysis.Loops)
        {
            if (loop.HeaderBlockId < 0 || loop.HeaderBlockId >= analysis.Blocks.Count) continue;
            if (infiniteLoopHeaders.Contains(analysis.Blocks[loop.HeaderBlockId].StartOffset)) continue;
            var reachesLatch = loop.Latches.ToHashSet();
            var pending = new Stack<int>(loop.Latches);
            while (pending.Count > 0)
            {
                int current = pending.Pop();
                foreach (var predecessor in analysis.Blocks[current].Predecessors)
                    if (reachesLatch.Add(predecessor.FromBlock))
                        pending.Push(predecessor.FromBlock);
            }
            var header = analysis.Blocks[loop.HeaderBlockId];
            foreach (var instruction in header.Instructions.Where(instruction =>
                         instruction.Name.StartsWith("POP_JUMP", StringComparison.Ordinal)))
            {
                var successors = analysis.Edges
                    .Where(edge => edge.SourceOffset == instruction.Offset && edge.Kind != StackEdgeKind.Exception)
                    .Select(edge => reachesLatch.Contains(edge.ToBlock))
                    .Distinct()
                    .ToList();
                if (successors.Count == 2) offsets.Add(instruction.Offset);
            }
        }
        return offsets;
    }

    Dictionary<int, int> BuildInfiniteLoopPlans()
    {
        var plans = new Dictionary<int, int>();
        for (int index = 0; index < ins.Count; index++)
        {
            var instruction = ins[index];
            if (instruction.Name is not ("JUMP_BACKWARD" or "JUMP_BACKWARD_NO_INTERRUPT") ||
                instruction.Target is not int target)
                continue;
            int header = IndexOfOffset(target);
            int afterJump = index + 1 < ins.Count ? index + 1 : ins.Count;
            if (header < 0 || ins[header].Name != "NOP" || !IsGeneratorCleanupTail(afterJump))
                continue;
            int end = index + 1 < ins.Count ? ins[index + 1].Offset : co.Code.Data.Length;
            if (!plans.TryGetValue(target, out int currentEnd) || end > currentEnd)
                plans[target] = end;
        }
        return plans;
    }

    bool IsGeneratorCleanupTail(int startIndex)
    {
        if (startIndex >= ins.Count) return false;
        for (int index = startIndex; index < ins.Count; index++)
            if (ins[index].Name is not ("CLEANUP_THROW" or "CALL_INTRINSIC_1" or "RERAISE" or
                "JUMP_BACKWARD_NO_INTERRUPT" or "POP_TOP" or "RETURN_CONST" or "RETURN_VALUE" or
                "RESUME" or "NOT_TAKEN"))
                return false;
        return true;
    }

    List<MatchPlan> BuildMatchPlans()
    {
        var bytecodePlans = BuildBytecodeMatchPlans();
        if (bytecodePlans.Count > 0) return bytecodePlans;

        var plans = new List<MatchPlan>();
        for (int index = 0; index < ins.Count; index++)
        {
            if (ins[index].Name != "COPY" || ins[index].Arg != 1) continue;
            var plan = new MatchPlan { StartIndex = index };
            int caseStart = index;
            while (caseStart < ins.Count && TryParseClassCase(caseStart, out var item, out int missIndex, out int nextStart))
            {
                plan.Cases.Add(item);
                if (nextStart >= ins.Count) { plan.EndIndex = nextStart; break; }
                if (IsClassPatternStart(nextStart))
                {
                    caseStart = nextStart;
                    continue;
                }

                if (ins[nextStart].Name == "NOP" &&
                    TryFindMatchArmEnd(nextStart + 1, out int wildcardBodyEnd, out int matchEnd))
                {
                    plan.Cases.Add(new MatchCasePlan
                    {
                        Pattern = "_",
                        BodyStartIndex = nextStart + 1,
                        BodyEndIndex = wildcardBodyEnd,
                    });
                    plan.EndIndex = matchEnd;
                }
                else
                    plan.EndIndex = nextStart;
                break;
            }
            if (plan.Cases.Count == 0 || plan.EndIndex <= plan.StartIndex ||
                !plan.Cases.Any(item => item.Pattern == "_")) continue;
            if (plan.Cases.Any(item => item.Pattern == "_") &&
                HasMatchCleanupTail(plan.EndIndex))
                plan.EndIndex = ins.Count;
            if (plans.Any(existing => existing.StartIndex < plan.EndIndex && existing.EndIndex > plan.StartIndex))
                continue;
            plans.Add(plan);
            index = plan.EndIndex - 1;
        }
        return plans;
    }

    List<MatchPlan> BuildBytecodeMatchPlans()
    {
        var plans = new List<MatchPlan>();
        var locations = LineTables.Decode(co, co.Code.Data.Length / 2);
        int LineAt(int index)
        {
            int unit = ins[index].Offset / 2;
            return unit >= 0 && unit < locations.Length ? locations[unit].Line : -1;
        }
        int LineStart(int index)
        {
            int line = LineAt(index);
            while (index > 0 && LineAt(index - 1) == line) index--;
            return index;
        }
        int PatternStart(int index)
        {
            int start = -1;
            for (int previous = index - 1; previous >= Math.Max(0, index - 10); previous--)
            {
                if (ins[previous].Name == "COPY" && ins[previous].Arg == 1)
                    return previous;
                if (ins[previous].Name is "RETURN_VALUE" or "RETURN_CONST" or "RAISE_VARARGS")
                    break;
            }
            return start >= 0 ? start : LineStart(index);
        }
        bool IsPatternOpcode(int index) =>
            index < ins.Count && ins[index].Name is "MATCH_MAPPING" or "MATCH_SEQUENCE" or "MATCH_CLASS";
        int FindPatternOpcode(int from)
        {
            for (int index = Math.Max(0, from); index < ins.Count; index++)
                if (IsPatternOpcode(index)) return index;
            return -1;
        }
        int FindBodyEnd(int start, int limit)
        {
            for (int index = start; index < limit; index++)
                if (ins[index].Name is "RETURN_VALUE" or "RETURN_CONST" or "RAISE_VARARGS")
                    return index + 1;
            return limit;
        }
        List<string> StoredNames(int index)
        {
            string opcode = ins[index].Name;
            if (opcode is "STORE_FAST" or "STORE_NAME" or "STORE_DEREF")
                return new List<string> { Operand(ins[index]) };
            if (opcode is "STORE_FAST_STORE_FAST" or "STORE_FAST_LOAD_FAST")
            {
                string[] names = Operand(ins[index]).Split(new[] { ", " }, StringSplitOptions.None);
                if (opcode == "STORE_FAST_STORE_FAST" && names.Length == 2)
                    return new List<string> { names[0], names[1] };
                return names.Length == 0 ? new List<string>() : new List<string> { names[0] };
            }
            return new List<string>();
        }
        bool IsStore(int index) =>
            index < ins.Count && ins[index].Name is "STORE_FAST" or "STORE_NAME" or "STORE_DEREF" or
                "STORE_FAST_STORE_FAST" or "STORE_FAST_LOAD_FAST";
        bool IsZeroInteger(int index) =>
            ins[index].Name == "LOAD_SMALL_INT" && ins[index].Arg == 0 ||
            ins[index].Name == "LOAD_CONST" && ins[index].RefIndex >= 0 &&
                ins[index].RefIndex < co.Consts.Count && co.Consts[ins[index].RefIndex] is PyInt value &&
                value.Value == 0;
        bool TryLiteralTest(int start, int limit, out string literal, out int branchIndex)
        {
            literal = null;
            branchIndex = -1;
            int index = start;
            while (index < limit && ins[index].Name is "COPY" or "DUP_TOP" or "NOT_TAKEN") index++;
            if (index >= limit || ins[index].Name != "LOAD_CONST" ||
                ins[index].RefIndex < 0 || ins[index].RefIndex >= co.Consts.Count)
                return false;
            int compare = index + 1;
            if (compare >= limit || ins[compare].Name != "COMPARE_OP") return false;
            branchIndex = compare + 1;
            if (branchIndex >= limit || !ins[branchIndex].Name.StartsWith("POP_JUMP", StringComparison.Ordinal) ||
                ins[branchIndex].Target is not int)
                return false;
            literal = co.Consts[ins[index].RefIndex].Repr();
            return true;
        }
        bool TryParseLiteralAlternatives(int start, int limit, int caseFailOffset,
            out string pattern, out int cursor)
        {
            pattern = null;
            cursor = start;
            if (!TryLiteralTest(start, limit, out string first, out int firstBranch) ||
                ins[firstBranch].Target is not int firstFailure)
                return false;
            var alternatives = new List<string> { first };
            if (firstFailure == caseFailOffset)
            {
                cursor = firstBranch + 1;
                while (cursor < limit && ins[cursor].Name == "NOT_TAKEN") cursor++;
                pattern = first;
                return true;
            }

            int mergeOffset = -1;
            int branch = firstBranch;
            while (true)
            {
                int success = branch + 1;
                while (success < limit && ins[success].Name == "NOT_TAKEN") success++;
                if (success >= limit || ins[success].Name is not ("JUMP_FORWARD" or "JUMP_ABSOLUTE") ||
                    ins[success].Target is not int successOffset)
                    return false;
                if (mergeOffset >= 0 && successOffset != mergeOffset) return false;
                mergeOffset = successOffset;

                if (ins[branch].Target is not int failureOffset) return false;
                int alternative = IndexOfOffset(failureOffset);
                if (alternative < 0 || alternative >= limit) return false;
                int probe = alternative;
                while (probe < limit && ins[probe].Name is "POP_TOP" or "NOT_TAKEN") probe++;
                if (probe < limit && ins[probe].Name is "JUMP_FORWARD" or "JUMP_ABSOLUTE" &&
                    ins[probe].Target == caseFailOffset)
                    break;
                if (!TryLiteralTest(alternative, limit, out string next, out int nextBranch))
                    return false;
                alternatives.Add(next);
                branch = nextBranch;
            }

            cursor = IndexOfOffset(mergeOffset);
            if (cursor < 0 || cursor >= limit) return false;
            while (cursor < limit && ins[cursor].Name is "POP_TOP" or "NOT_TAKEN") cursor++;
            if (IsStore(cursor))
            {
                var names = StoredNames(cursor);
                if (names.Count == 1 && ins[cursor].Name != "STORE_FAST_LOAD_FAST")
                {
                    pattern = "(" + string.Join(" | ", alternatives) + ") as " + names[0];
                    cursor++;
                    return true;
                }
            }
            pattern = "(" + string.Join(" | ", alternatives) + ")";
            return true;
        }
        bool TryParseSequencePattern(int unpackIndex, int limit, int caseFailOffset,
            out string pattern, out int cursor)
        {
            pattern = null;
            cursor = unpackIndex + 1;
            int before, after;
            bool hasStar = ins[unpackIndex].Name == "UNPACK_EX";
            if (hasStar)
            {
                before = ins[unpackIndex].Arg & 0xFF;
                after = ins[unpackIndex].Arg >> 8;
            }
            else
            {
                before = ins[unpackIndex].Arg;
                after = 0;
            }
            int count = before + after + (hasStar ? 1 : 0);
            var parts = new List<string>();
            for (int field = 0; field < count; field++)
            {
                while (cursor < limit && ins[cursor].Name is "COPY" or "DUP_TOP" or "NOT_TAKEN") cursor++;
                if (cursor >= limit) return false;
                if (IsStore(cursor))
                {
                    var names = StoredNames(cursor);
                    if (names.Count == 0) return false;
                    string name = names[0];
                    if (ins[cursor].Name == "STORE_FAST_STORE_FAST" && names.Count > 1) return false;
                    parts.Add(hasStar && field == before ? "*" + name : name);
                    cursor++;
                    continue;
                }
                if (!TryParseLiteralAlternatives(cursor, limit, caseFailOffset, out string part, out int afterPart))
                    return false;
                parts.Add(part);
                cursor = afterPart;
            }
            pattern = "[" + string.Join(", ", parts) + "]";
            return true;
        }

        for (int anchor = FindPatternOpcode(0); anchor >= 0;)
        {
            int firstCaseStart = PatternStart(anchor);
            var candidate = new MatchPlan { StartIndex = firstCaseStart };
            int caseAnchor = anchor;
            bool complete = false;
            int matchEnd = -1;

            while (caseAnchor >= 0)
            {
                string opcode = ins[caseAnchor].Name;
                int caseLine = LineAt(caseAnchor);
                int failBranch = -1;
                for (int index = caseAnchor + 1; index < ins.Count; index++)
                {
                    if (ins[index].Name.StartsWith("POP_JUMP", StringComparison.Ordinal))
                    {
                        failBranch = index;
                        break;
                    }
                    if (ins[index].Name is "RETURN_VALUE" or "RETURN_CONST" or "RAISE_VARARGS")
                        break;
                }
                if (failBranch < 0 || ins[failBranch].Target is not int failOffset) break;
                int failIndex = IndexOfOffset(failOffset);
                if (failIndex < 0) break;

                int nextAnchor = FindPatternOpcode(failIndex);
                int nextCaseStart = nextAnchor >= 0 ? PatternStart(nextAnchor) : -1;
                int patternLimit = nextCaseStart >= 0 ? nextCaseStart : ins.Count;
                int cursor;
                string pattern;
                string guardAlias = null;
                string patternAlias = null;
                if (opcode == "MATCH_MAPPING")
                {
                    int keysIndex = -1;
                    for (int index = caseAnchor + 1; index < patternLimit; index++)
                        if (ins[index].Name == "MATCH_KEYS") { keysIndex = index; break; }
                    if (keysIndex < 0) break;
                    int tupleIndex = -1;
                    for (int index = keysIndex - 1; index > caseAnchor; index--)
                    {
                        if (ins[index].Name == "LOAD_CONST") { tupleIndex = index; break; }
                    }
                    if (tupleIndex < 0 || ins[tupleIndex].RefIndex < 0 ||
                        ins[tupleIndex].RefIndex >= co.Consts.Count ||
                        co.Consts[ins[tupleIndex].RefIndex] is not PyTuple keys)
                        break;
                    int unpackIndex = -1;
                    for (int index = keysIndex + 1; index < patternLimit; index++)
                        if (ins[index].Name == "UNPACK_SEQUENCE") { unpackIndex = index; break; }
                    if (unpackIndex >= 0 && ins[unpackIndex].Arg != keys.Items.Count) break;

                    var fields = new string[keys.Items.Count];
                    cursor = unpackIndex >= 0 ? unpackIndex + 1 : keysIndex + 1;
                    string restName = null;
                    while (cursor < patternLimit && !IsStore(cursor))
                        cursor++;
                    if (cursor >= patternLimit) break;
                    bool restFirst = ins.Skip(keysIndex + 1)
                        .Take(Math.Max(0, cursor - keysIndex - 1))
                        .Any(instruction => instruction.Name == "DICT_UPDATE");
                    bool restAfterValues = ins.Skip(keysIndex + 1)
                        .Take(Math.Max(0, cursor - keysIndex - 1))
                        .Any(instruction => instruction.Name == "COPY_DICT_WITHOUT_KEYS");
                    var stores = StoredNames(cursor);
                    if (ins[cursor].Name == "STORE_FAST_STORE_FAST" && stores.Count == 2 &&
                        keys.Items.Count == 1)
                    {
                        restName = stores[0];
                        fields[0] = stores[1];
                        cursor++;
                    }
                    else
                    {
                        if (restFirst)
                        {
                            if (stores.Count == 0) break;
                            restName = stores[0];
                            cursor++;
                            while (cursor < patternLimit && !IsStore(cursor))
                                cursor++;
                        }
                        int field = 0;
                        while (cursor < patternLimit && field < fields.Length && IsStore(cursor))
                        {
                            var fieldStores = StoredNames(cursor);
                            if (fieldStores.Count == 0) break;
                            fields[field++] = fieldStores[0];
                            cursor++;
                        }
                        if (field != fields.Length) break;
                        if (restAfterValues && cursor < patternLimit && IsStore(cursor))
                        {
                            var restStores = StoredNames(cursor);
                            if (restStores.Count > 0) restName = restStores[0];
                            cursor++;
                        }
                    }
                    if (fields.Any(string.IsNullOrEmpty)) break;
                    pattern = "{" + string.Join(", ", keys.Items.Select((key, index) =>
                        key.Repr() + ": " + fields[index])) +
                        (restName == null ? "" : ", **" + restName) + "}";
                }
                else if (opcode == "MATCH_SEQUENCE")
                {
                    int unpackIndex = -1;
                    for (int index = caseAnchor + 1; index < patternLimit; index++)
                    {
                        if (ins[index].Name is "UNPACK_SEQUENCE" or "UNPACK_EX")
                        {
                            unpackIndex = index;
                            break;
                        }
                    }
                    if (unpackIndex < 0)
                    {
                        int zeroIndex = -1;
                        for (int index = caseAnchor + 1; index + 2 < patternLimit; index++)
                        {
                            if (IsZeroInteger(index) && ins[index + 1].Name == "COMPARE_OP")
                            {
                                zeroIndex = index;
                                break;
                            }
                        }
                        if (zeroIndex < 0 || failOffset < 0) break;
                        bool hasNoneAlternative = false;
                        for (int index = failIndex; index < patternLimit; index++)
                        {
                            if (ins[index].Name.StartsWith("POP_JUMP", StringComparison.Ordinal) &&
                                ins[index].Name.EndsWith("IF_NOT_NONE", StringComparison.Ordinal))
                            {
                                hasNoneAlternative = true;
                                break;
                            }
                            if (ins[index].Name == "IS_OP" && index + 1 < patternLimit &&
                                ins[index + 1].Name.StartsWith("POP_JUMP", StringComparison.Ordinal))
                            {
                                hasNoneAlternative = true;
                                break;
                            }
                            if (ins[index].Name == "RETURN_VALUE" || IsPatternOpcode(index)) break;
                        }
                        if (!hasNoneAlternative) break;
                        int emptyBodyStart = -1;
                        for (int index = caseAnchor + 1; index < patternLimit; index++)
                        {
                            if (LineAt(index) > caseLine)
                            {
                                emptyBodyStart = index;
                                break;
                            }
                        }
                        int emptyBodyLimit = nextCaseStart >= 0 ? nextCaseStart : ins.Count;
                        if (emptyBodyStart < 0) break;
                        while (emptyBodyStart < emptyBodyLimit && ins[emptyBodyStart].Name is "POP_TOP" or "NOT_TAKEN")
                            emptyBodyStart++;
                        int emptyBodyEnd = FindBodyEnd(emptyBodyStart, emptyBodyLimit);
                        if (emptyBodyStart >= emptyBodyEnd) break;
                        candidate.Cases.Add(new MatchCasePlan { Pattern = "[]", BodyStartIndex = emptyBodyStart, BodyEndIndex = emptyBodyEnd });
                        candidate.Cases.Add(new MatchCasePlan { Pattern = "None", BodyStartIndex = emptyBodyStart, BodyEndIndex = emptyBodyEnd });
                        caseAnchor = nextAnchor;
                        if (caseAnchor < 0) break;
                        continue;
                    }

                    if (!TryParseSequencePattern(unpackIndex, patternLimit, failOffset, out pattern, out cursor))
                        break;
                    if (cursor < patternLimit && ins[cursor].Name == "STORE_FAST_LOAD_FAST")
                    {
                        var names = StoredNames(cursor);
                        if (names.Count > 0)
                        {
                            guardAlias = names[0];
                            cursor++;
                        }
                    }
                }
                else
                {
                    int classStart = LineStart(caseAnchor);
                    int classIndex = -1, tupleIndex = -1;
                    for (int index = classStart; index < caseAnchor; index++)
                    {
                        if (ins[index].Name is "LOAD_GLOBAL" or "LOAD_NAME" or "LOAD_FAST" or "LOAD_DEREF")
                            classIndex = index;
                        if (ins[index].Name == "LOAD_CONST") tupleIndex = index;
                    }
                    if (classIndex < 0) break;
                    string className = ins[classIndex].Name is "LOAD_GLOBAL" or "LOAD_NAME"
                        ? NameOf(ins[classIndex])
                        : Operand(ins[classIndex]);
                    List<string> keywordNames = new();
                    if (tupleIndex >= 0 && ins[tupleIndex].RefIndex >= 0 &&
                        ins[tupleIndex].RefIndex < co.Consts.Count &&
                        co.Consts[ins[tupleIndex].RefIndex] is PyTuple keywordTuple)
                        keywordNames = keywordTuple.Items.Select(value =>
                            value is PyStr text ? text.Value : null).ToList();
                    int unpackIndex = -1;
                    for (int index = caseAnchor + 1; index < patternLimit; index++)
                        if (ins[index].Name == "UNPACK_SEQUENCE") { unpackIndex = index; break; }
                    int positionalCount = ins[caseAnchor].Arg;
                    int captureCount = unpackIndex >= 0 ? ins[unpackIndex].Arg : positionalCount;
                    var captures = new List<string>();
                    cursor = unpackIndex >= 0 ? unpackIndex + 1 : caseAnchor + 1;
                    while (unpackIndex >= 0 && cursor < patternLimit && captures.Count < captureCount)
                    {
                        var names = StoredNames(cursor);
                        if (names.Count == 0) break;
                        captures.AddRange(names);
                        if (ins[cursor].Name == "STORE_FAST_LOAD_FAST" && names.Count > 0)
                            guardAlias = names[0];
                        cursor++;
                    }
                    while (unpackIndex < 0 && cursor < patternLimit && captures.Count < captureCount)
                    {
                        var names = StoredNames(cursor);
                        if (names.Count > 0)
                        {
                            captures.AddRange(names);
                            cursor++;
                            continue;
                        }
                        cursor++;
                    }
                    if (unpackIndex < 0 && captureCount == 0)
                    {
                        cursor = caseAnchor + 1;
                        while (cursor < patternLimit &&
                            !ins[cursor].Name.StartsWith("POP_JUMP", StringComparison.Ordinal))
                            cursor++;
                        if (cursor < patternLimit) cursor++;
                    }
                    bool aliasOnly = captureCount == 0 && cursor < patternLimit &&
                        ins[cursor].Name == "STORE_FAST_LOAD_FAST";
                    if (aliasOnly)
                    {
                        var names = Operand(ins[cursor]).Split(new[] { ", " }, StringSplitOptions.None);
                        if (names.Length == 2 && names[0] == names[1])
                        {
                            guardAlias = names[0];
                            patternAlias = names[0];
                            cursor++;
                        }
                    }
                    if (positionalCount > captures.Count ||
                        keywordNames.Count > captures.Count - positionalCount)
                    {
                        if (!aliasOnly || positionalCount != 0 || keywordNames.Count != 0) break;
                    }
                    var patternParts = captures.Take(positionalCount).ToList();
                    for (int index = 0; index < keywordNames.Count; index++)
                    {
                        if (string.IsNullOrEmpty(keywordNames[index])) { patternParts.Clear(); break; }
                        patternParts.Add(keywordNames[index] + "=" + captures[positionalCount + index]);
                    }
                    if (positionalCount > 0 && patternParts.Count == 0) break;
                    pattern = className + "(" + string.Join(", ", patternParts) + ")" +
                        (patternAlias == null ? "" : " as " + patternAlias);
                }

                int nextPatternAnchor = FindPatternOpcode(failIndex);
                int nextPatternStart = nextPatternAnchor >= 0 ? PatternStart(nextPatternAnchor) : -1;
                int guardBranch = -1;
                if (nextPatternStart >= 0)
                {
                    for (int index = cursor; index < nextPatternStart; index++)
                    {
                        if (ins[index].Name.StartsWith("POP_JUMP", StringComparison.Ordinal) &&
                            ins[index].Target == ins[nextPatternStart].Offset)
                        {
                            guardBranch = index;
                            break;
                        }
                    }
                }

                var matchCase = new MatchCasePlan { Pattern = pattern, GuardAlias = guardAlias };
                int bodyStart;
                if (guardBranch >= 0)
                {
                    int guardStart = cursor;
                    while (guardStart < guardBranch && ins[guardStart].Name is "POP_TOP" or "NOT_TAKEN")
                        guardStart++;
                    matchCase.GuardStartIndex = guardStart;
                    matchCase.GuardEndIndex = guardBranch;
                    bodyStart = guardBranch + 1;
                    while (bodyStart < ins.Count && ins[bodyStart].Name is "NOT_TAKEN" or "POP_TOP")
                        bodyStart++;
                }
                else
                {
                    bodyStart = cursor;
                    while (bodyStart < ins.Count && ins[bodyStart].Name is "POP_TOP" or "NOT_TAKEN")
                        bodyStart++;
                    if (bodyStart < ins.Count &&
                        ins[bodyStart].Name is "JUMP_FORWARD" or "JUMP_ABSOLUTE" &&
                        ins[bodyStart].Target is int successOffset)
                        bodyStart = IndexOfOffset(successOffset);
                }
                int bodyLimit = nextPatternStart >= 0 && bodyStart < nextPatternStart
                    ? nextPatternStart
                    : ins.Count;
                int bodyEnd = FindBodyEnd(bodyStart, bodyLimit);
                if (bodyStart >= bodyEnd) break;
                matchCase.BodyStartIndex = bodyStart;
                matchCase.BodyEndIndex = bodyEnd;
                candidate.Cases.Add(matchCase);

                if (nextPatternAnchor >= 0)
                {
                    caseAnchor = nextPatternAnchor;
                    continue;
                }

                int wildcardSearchStart = failIndex;
                while (wildcardSearchStart < ins.Count &&
                    ins[wildcardSearchStart].Name is "POP_TOP" or "NOT_TAKEN")
                    wildcardSearchStart++;
                if (wildcardSearchStart < ins.Count &&
                    ins[wildcardSearchStart].Name is "JUMP_FORWARD" or "JUMP_ABSOLUTE" &&
                    ins[wildcardSearchStart].Target is int wildcardTarget)
                    wildcardSearchStart = IndexOfOffset(wildcardTarget);
                int wildcard = -1;
                for (int index = Math.Max(0, wildcardSearchStart); index < ins.Count; index++)
                {
                    if (ins[index].Name == "NOP" && LineAt(index) >= caseLine ||
                        LineAt(index) > caseLine && ins[index].Name is not ("POP_TOP" or "NOT_TAKEN"))
                    {
                        wildcard = index;
                        break;
                    }
                    if (ins[index].Name is "RETURN_VALUE" or "RETURN_CONST" or "RAISE_VARARGS")
                        break;
                }
                if (wildcard < 0) break;
                int wildcardBody = ins[wildcard].Name == "NOP" ? wildcard + 1 : wildcard;
                int wildcardEnd = FindBodyEnd(wildcardBody, ins.Count);
                if (wildcardBody >= wildcardEnd) break;
                candidate.Cases.Add(new MatchCasePlan
                {
                    Pattern = "_",
                    BodyStartIndex = wildcardBody,
                    BodyEndIndex = wildcardEnd,
                });
                matchEnd = wildcardEnd;
                complete = true;
                break;
            }

            if (complete && candidate.Cases.Count > 1)
            {
                candidate.EndIndex = matchEnd;
                if (HasMatchCleanupTail(candidate.EndIndex)) candidate.EndIndex = ins.Count;
                if (!plans.Any(existing => existing.StartIndex < candidate.EndIndex &&
                    existing.EndIndex > candidate.StartIndex))
                    plans.Add(candidate);
                anchor = FindPatternOpcode(candidate.EndIndex);
            }
            else
                anchor = FindPatternOpcode(anchor + 1);
        }
        return plans;
    }

    bool HasMatchCleanupTail(int startIndex)
    {
        if (startIndex >= ins.Count || co.ExceptionTable.Length == 0) return false;
        bool hasReraise = false;
        for (int index = startIndex; index < ins.Count; index++)
        {
            string name = ins[index].Name;
            if (name == "RERAISE") hasReraise = true;
            else if (name is not ("SWAP" or "POP_TOP" or "STORE_FAST" or "STORE_FAST_STORE_FAST" or
                         "STORE_DEREF" or "DELETE_FAST" or "COPY" or "POP_EXCEPT" or "PUSH_EXC_INFO"))
                return false;
        }
        return hasReraise;
    }

    bool IsClassPatternStart(int index) =>
        index < ins.Count && (ins[index].Name == "COPY" && ins[index].Arg == 1 ||
            ins[index].Name is "LOAD_GLOBAL" or "LOAD_NAME");

    bool TryParseClassCase(int startIndex, out MatchCasePlan matchCase, out int missIndex, out int nextStart)
    {
        matchCase = null;
        missIndex = -1;
        nextStart = -1;
        int matchIndex = -1;
        for (int index = startIndex + 1; index < Math.Min(ins.Count, startIndex + 8); index++)
        {
            if (ins[index].Name == "MATCH_CLASS") { matchIndex = index; break; }
            if (ins[index].Name.StartsWith("POP_JUMP", StringComparison.Ordinal)) return false;
        }
        if (matchIndex < 0) return false;
        int classIndex = -1, tupleIndex = -1;
        for (int index = startIndex; index < matchIndex; index++)
        {
            if (ins[index].Name is "LOAD_GLOBAL" or "LOAD_NAME" or "LOAD_FAST" or "LOAD_DEREF")
                classIndex = index;
            if (ins[index].Name == "LOAD_CONST") tupleIndex = index;
        }
        if (classIndex < 0) return false;
        string className = ins[classIndex].Name is "LOAD_GLOBAL" or "LOAD_NAME"
            ? NameOf(ins[classIndex])
            : Operand(ins[classIndex]);
        List<string> keywordNames = new();
        if (tupleIndex >= 0 && ins[tupleIndex].RefIndex >= 0 &&
            ins[tupleIndex].RefIndex < co.Consts.Count && co.Consts[ins[tupleIndex].RefIndex] is PyTuple tuple)
            keywordNames = tuple.Items.Select(value => value is PyStr text ? text.Value : null).ToList();

        int matchBranch = matchIndex + 1;
        while (matchBranch < ins.Count && ins[matchBranch].Name == "COPY") matchBranch++;
        if (matchBranch >= ins.Count || ins[matchBranch].Name != "POP_JUMP_IF_NONE" ||
            ins[matchBranch].Target is not int missOffset) return false;
        missIndex = IndexOfOffset(missOffset);
        if (missIndex < 0 || ins[missIndex].Name != "POP_TOP") return false;
        nextStart = missIndex + 1;

        int successIndex = matchBranch + 1;
        if (successIndex < ins.Count && ins[successIndex].Name == "NOT_TAKEN") successIndex++;
        if (successIndex >= ins.Count || ins[successIndex].Name != "UNPACK_SEQUENCE") return false;
        int unpackCount = ins[successIndex].Arg;
        int cursor = successIndex + 1;
        var captures = new List<string>();
        while (cursor < ins.Count && captures.Count < unpackCount)
        {
            string opcode = ins[cursor].Name;
            if (opcode is "STORE_FAST" or "STORE_NAME" or "STORE_DEREF")
            {
                captures.Add(Operand(ins[cursor++]));
                continue;
            }
            if (opcode is "STORE_FAST_STORE_FAST" or "STORE_FAST_LOAD_FAST")
            {
                var names = Operand(ins[cursor++]).Split(", ");
                captures.Add(names[0]);
                if (opcode == "STORE_FAST_STORE_FAST") captures.Add(names[1]);
                continue;
            }
            break;
        }
        if (captures.Count != unpackCount) return false;
        int positionalCount = ins[matchIndex].Arg;
        if (positionalCount > captures.Count || keywordNames.Count > captures.Count - positionalCount) return false;
        var patternParts = captures.Take(positionalCount).ToList();
        for (int index = 0; index < keywordNames.Count; index++)
        {
            if (string.IsNullOrEmpty(keywordNames[index])) return false;
            patternParts.Add(keywordNames[index] + "=" + captures[positionalCount + index]);
        }
        string pattern = className + (patternParts.Count == 0 ? "()" : "(" + string.Join(", ", patternParts) + ")");

        var item = new MatchCasePlan { Pattern = pattern };
        int successPop = cursor;
        if (successPop < ins.Count && ins[successPop].Name == "POP_TOP")
        {
            item.BodyStartIndex = successPop + 1;
        }
        else
        {
            int guardBranch = -1;
            for (int index = cursor; index < missIndex; index++)
            {
                if (ins[index].Name.StartsWith("POP_JUMP", StringComparison.Ordinal) &&
                    ins[index].Target == ins[nextStart].Offset)
                {
                    guardBranch = index;
                    break;
                }
            }
            if (guardBranch >= 0)
            {
                int bodyIndex = guardBranch + 1;
                if (bodyIndex < ins.Count && ins[bodyIndex].Name == "NOT_TAKEN") bodyIndex++;
                if (bodyIndex >= ins.Count || ins[bodyIndex].Name != "POP_TOP") return false;
                item.GuardStartIndex = cursor;
                item.GuardEndIndex = guardBranch;
                item.BodyStartIndex = bodyIndex + 1;
            }
            else
                item.BodyStartIndex = cursor;
        }

        item.BodyEndIndex = missIndex;
        for (int index = item.BodyStartIndex; index < missIndex; index++)
        {
            if (ins[index].Name is "RETURN_VALUE" or "RETURN_CONST" or "RAISE_VARARGS")
            {
                item.BodyEndIndex = index + 1;
                break;
            }
            if (ins[index].Target is int target && ins[index].Name.StartsWith("JUMP", StringComparison.Ordinal) &&
                target > ins[index].Offset && target >= ins[missIndex].Offset)
            {
                item.BodyEndIndex = index;
                break;
            }
        }
        if (item.BodyStartIndex > item.BodyEndIndex) return false;
        matchCase = item;
        return true;
    }

    bool TryFindMatchArmEnd(int startIndex, out int bodyEnd, out int matchEnd)
    {
        bodyEnd = -1;
        matchEnd = -1;
        for (int index = startIndex; index < ins.Count; index++)
        {
            if (ins[index].Name is "RETURN_VALUE" or "RETURN_CONST" or "RAISE_VARARGS")
            {
                bodyEnd = index + 1;
                matchEnd = index + 1;
                return true;
            }
            if (ins[index].Target is int target && ins[index].Name.StartsWith("JUMP", StringComparison.Ordinal) &&
                target > ins[index].Offset)
            {
                bodyEnd = index;
                matchEnd = IndexOfOffset(target);
                return matchEnd > startIndex;
            }
            if (ins[index].Name.StartsWith("POP_JUMP", StringComparison.Ordinal)) return false;
        }
        return false;
    }

    void EmitMatch(MatchPlan plan)
    {
        if (stack.Count == 0) throw new DecompileException("A match statement has no subject on the evaluation stack.");
        var subject = Pop();
        Emit("match " + Strip(subject.S) + ":");
        ind++;
        foreach (var matchCase in plan.Cases)
        {
            string guard = null;
            if (matchCase.GuardStartIndex >= 0)
            {
                if (matchCase.GuardAlias != null)
                    Push(new Ex(matchCase.GuardAlias));
                int lineCount = lines.Count;
                for (int index = matchCase.GuardStartIndex; index < matchCase.GuardEndIndex; index++)
                {
                    currentOffset = ins[index].Offset;
                    int next = index + 1 < ins.Count ? ins[index + 1].Offset : co.Code.Data.Length;
                    Step(index, ins[index], ins[index].Offset, next);
                }
                if (lines.Count != lineCount || stack.Count == 0)
                    throw new DecompileException("A match guard could not be reconstructed as an expression.");
                guard = Strip(Pop().S);
                stack.Clear();
            }
            Emit("case " + matchCase.Pattern + (guard == null ? "" : " if " + guard) + ":");
            int headerIndex = lines.Count - 1;
            ind++;
            for (int index = matchCase.BodyStartIndex; index < matchCase.BodyEndIndex; index++)
            {
                currentOffset = ins[index].Offset;
                int next = index + 1 < ins.Count ? ins[index + 1].Offset : co.Code.Data.Length;
                CloseBlocks(ins[index].Offset);
                Step(index, ins[index], ins[index].Offset, next);
            }
            CloseBlocks(matchCase.BodyEndIndex < ins.Count
                ? ins[matchCase.BodyEndIndex].Offset
                : co.Code.Data.Length);
            if (lines.Count - 1 == headerIndex) Emit("pass");
            ind--;
            stack.Clear();
        }
        ind--;
    }

    List<SimpleTryPlan> BuildSimpleTryPlans()
    {
        var plans = new List<SimpleTryPlan>();
        if (t.Minor < 11 || co.ExceptionTable.Length == 0)
        {
            plans = BuildLegacyFinallyPlans();
            plans.AddRange(BuildLegacyExceptPlans());
            return plans;
        }

        var entries = LineTables.DecodeExc(co.ExceptionTable);
        var byOffset = ins.Select((instruction, index) => (instruction.Offset, index))
            .ToDictionary(pair => pair.Offset, pair => pair.index);
        var finallyTargets = entries.Select(entry => entry.Target * 2).Distinct()
            .Where(target => byOffset.TryGetValue(target, out int index) &&
                ins[index].Name == "PUSH_EXC_INFO" &&
                !ins.Skip(index).TakeWhile(instruction => instruction.Name != "RERAISE")
                    .Any(instruction => instruction.Name is "CHECK_EXC_MATCH" or "WITH_EXCEPT_START"))
            .ToHashSet();
        var locations = LineTables.Decode(co, co.Code.Data.Length / 2);
        int SourceLine(int index)
        {
            int unit = ins[index].Offset / 2;
            return unit >= 0 && unit < locations.Length ? locations[unit].Line : -1;
        }
        bool IsReturnCleanup(int index, int start, int end)
        {
            if (ins[index].Name is "SWAP" or "RETURN_VALUE" or "RETURN_CONST") return true;
            if (ins[index].Name != "POP_TOP") return false;
            for (int previous = index - 1; previous >= start && previous < end; previous--)
            {
                if (ins[previous].Name == "SWAP") return true;
                if (ins[previous].Name is not ("POP_TOP" or "NOT_TAKEN")) return false;
            }
            return false;
        }
        foreach (var group in entries.GroupBy(entry => entry.Target * 2))
        {
            if (!byOffset.TryGetValue(group.Key, out int handlerIndex) ||
                ins[handlerIndex].Name != "PUSH_EXC_INFO") continue;
            var protectedRanges = group.Where(entry => entry.End * 2 != group.Key).ToList();
            if (protectedRanges.Count == 0) protectedRanges = group.ToList();
            int protectedEnd = protectedRanges.Max(entry => entry.End) * 2;
            int protectedEndIndex = ins.FindIndex(instruction => instruction.Offset >= protectedEnd);
            if (protectedEndIndex < 0) continue;
            var plan = new SimpleTryPlan
            {
                StartOffset = group.Min(entry => entry.Start) * 2,
                HandlerOffset = group.Key,
            };
            if (!byOffset.ContainsKey(plan.StartOffset)) continue;
            var finallyRange = entries.FirstOrDefault(entry =>
                entry.Start * 2 == protectedEnd && finallyTargets.Contains(entry.Target * 2));
            if (finallyRange == default)
            {
                finallyRange = entries
                    .Where(entry => entry.Start * 2 >= plan.HandlerOffset &&
                        finallyTargets.Contains(entry.Target * 2) &&
                        entry.Target * 2 > plan.HandlerOffset)
                    .OrderBy(entry => entry.Start)
                    .FirstOrDefault();
            }
            bool directFinally = finallyRange == default && finallyTargets.Contains(group.Key);
            if (finallyRange != default || directFinally)
            {
                plan.HasFinally = true;
                plan.FinallyHandlerOffset = directFinally ? group.Key : finallyRange.Target * 2;
                int handlerIndexForFinally = IndexOfOffset(plan.FinallyHandlerOffset);
                if (handlerIndexForFinally < 0) continue;
                int firstFinallyLine = -1;
                var finallyLines = new HashSet<int>();
                for (int index = handlerIndexForFinally + 1; index < ins.Count; index++)
                {
                    if (ins[index].Name == "RERAISE") break;
                    int line = SourceLine(index);
                    if (line > 0)
                    {
                        firstFinallyLine = firstFinallyLine < 0 ? line : firstFinallyLine;
                        finallyLines.Add(line);
                    }
                }
                int inlineFinallyIndex = firstFinallyLine < 0
                    ? -1
                    : Enumerable.Range(protectedEndIndex, Math.Max(0, handlerIndexForFinally - protectedEndIndex))
                        .FirstOrDefault(index => SourceLine(index) == firstFinallyLine, -1);
                if (inlineFinallyIndex < 0) continue;
                plan.FinallyStartOffset = ins[inlineFinallyIndex].Offset;
                int finallyEndIndex = inlineFinallyIndex;
                for (; finallyEndIndex < handlerIndexForFinally; finallyEndIndex++)
                {
                    string name = ins[finallyEndIndex].Name;
                    if (name is "RETURN_VALUE" or "RETURN_CONST")
                    {
                        if (finallyEndIndex > inlineFinallyIndex &&
                            ins[finallyEndIndex - 1].Name == "LOAD_CONST" &&
                            ins[finallyEndIndex - 1].RefIndex >= 0 &&
                            ins[finallyEndIndex - 1].RefIndex < co.Consts.Count &&
                            co.Consts[ins[finallyEndIndex - 1].RefIndex] is PyNone)
                            finallyEndIndex--;
                        break;
                    }
                    int line = SourceLine(finallyEndIndex);
                    if (finallyEndIndex > inlineFinallyIndex && line > 0 && !finallyLines.Contains(line))
                        break;
                }
                if (finallyEndIndex <= inlineFinallyIndex) continue;
                plan.FinallyEndOffset = ins[finallyEndIndex].Offset;
                if (finallyTargets.Contains(plan.HandlerOffset))
                {
                    for (int index = handlerIndex; index < ins.Count; index++)
                    {
                        plan.SkippedOffsets.Add(ins[index].Offset);
                        if (ins[index].Name == "RERAISE") break;
                    }
                }
                for (int index = handlerIndexForFinally; index < ins.Count; index++)
                    plan.SkippedOffsets.Add(ins[index].Offset);
            }
            bool foundNormalBoundary = false;
            bool hasElseBody = false;
            var handlerCase = ParseExceptCase(handlerIndex);
            bool hasExplicitExcept = handlerCase != null;
            for (int index = protectedEndIndex; index < ins.Count && ins[index].Offset < plan.HandlerOffset; index++)
            {
                if (plan.HasFinally && ins[index].Offset >= plan.FinallyStartOffset)
                {
                    plan.HasElse = hasElseBody;
                    plan.TryEndOffset = protectedEnd;
                    plan.ElseEndOffset = plan.FinallyStartOffset;
                    foundNormalBoundary = true;
                    break;
                }
                string name = ins[index].Name;
                if (hasExplicitExcept && plan.HasFinally && name is "RETURN_VALUE" or "RETURN_CONST")
                {

                    continue;
                }
                if (name is "RETURN_VALUE" or "RETURN_CONST" or "RAISE_VARARGS")
                {
                    int endOffset = index + 1 < ins.Count ? ins[index + 1].Offset : co.Code.Data.Length;
                    plan.HasElse = hasElseBody;
                    plan.TryEndOffset = plan.HasElse ? protectedEnd : endOffset;
                    plan.ElseEndOffset = endOffset;
                    foundNormalBoundary = true;
                    break;
                }
                if (name.StartsWith("JUMP", StringComparison.Ordinal))
                {
                    plan.HasElse = hasElseBody;
                    plan.TryEndOffset = plan.HasElse ? protectedEnd : ins[index].Offset;
                    plan.ElseEndOffset = ins[index].Offset;
                    plan.SkippedOffsets.Add(ins[index].Offset);
                    foundNormalBoundary = true;
                    break;
                }
                if (name is "END_FOR" or "POP_ITER")
                {
                    plan.TryEndOffset = ins[index].Offset;
                    foundNormalBoundary = true;
                    break;
                }
                if (name is not ("NOP" or "SWAP" or "POP_TOP"))
                    hasElseBody = true;
            }
            if (!foundNormalBoundary && hasExplicitExcept)
            {
                plan.TryEndOffset = protectedEnd;
                plan.ElseEndOffset = plan.HasFinally ? plan.FinallyStartOffset : protectedEnd;
                plan.HasElse = false;
                foundNormalBoundary = true;
            }
            var explicitHandler = hasExplicitExcept ? handlerCase : null;
            if (explicitHandler == null && (!foundNormalBoundary || plan.TryEndOffset < protectedEnd || plan.TryEndOffset > plan.HandlerOffset ||
                (plan.HasElse && (plan.ElseEndOffset < plan.TryEndOffset || plan.ElseEndOffset > plan.HandlerOffset))))
                continue;
            if (explicitHandler != null)
            {
                plan.TryEndOffset = Math.Max(protectedEnd, plan.TryEndOffset);
                if (plan.HasFinally && plan.ElseEndOffset == 0) plan.ElseEndOffset = plan.FinallyStartOffset;
            }

            int caseIndex = handlerIndex;
            while (caseIndex < ins.Count)
            {
                var exceptionCase = ParseExceptCase(caseIndex);
                if (exceptionCase == null)
                {
                    plan.Cases.Clear();
                    break;
                }
                plan.Cases.Add(exceptionCase);
                int headerIndex = byOffset[exceptionCase.HeaderOffset];
                int bodyEndIndex = byOffset.TryGetValue(exceptionCase.BodyEndOffset, out int endIndex)
                    ? endIndex : ins.Count;
                for (int index = headerIndex; index < bodyEndIndex; index++)
                    plan.SkippedOffsets.Add(ins[index].Offset);
                int mismatchIndex = exceptionCase.MismatchOffset < 0 ? -1 : IndexOfOffset(exceptionCase.MismatchOffset);
                int cleanupEnd = mismatchIndex >= bodyEndIndex ? mismatchIndex : bodyEndIndex;
                if (mismatchIndex < 0)
                {
                    cleanupEnd = bodyEndIndex + 1;
                    while (cleanupEnd < ins.Count && !ins[cleanupEnd].Name.StartsWith("JUMP", StringComparison.Ordinal))
                        cleanupEnd++;
                    if (cleanupEnd < ins.Count) cleanupEnd++;
                }
                for (int index = bodyEndIndex; index < cleanupEnd && index < ins.Count; index++)
                    plan.SkippedOffsets.Add(ins[index].Offset);

                if (mismatchIndex < 0 || ins[mismatchIndex].Name == "RERAISE")
                {
                    if (mismatchIndex >= 0)
                    {
                        for (int index = mismatchIndex; index < ins.Count &&
                             (!plan.HasFinally || ins[index].Offset < plan.FinallyHandlerOffset);)
                        {
                            string cleanupName = ins[index].Name;
                            if (cleanupName is "RERAISE" or "COPY" or "POP_EXCEPT" or "SWAP" or "NOT_TAKEN" or "NOP")
                            {
                                plan.SkippedOffsets.Add(ins[index++].Offset);
                                continue;
                            }
                            if (cleanupName == "LOAD_CONST" &&
                                ins[index].RefIndex >= 0 &&
                                ins[index].RefIndex < co.Consts.Count &&
                                co.Consts[ins[index].RefIndex] is PyNone &&
                                index + 2 < ins.Count &&
                                ins[index + 1].Name is "STORE_FAST" or "STORE_DEREF" &&
                                ins[index + 2].Name is "DELETE_FAST" or "DELETE_DEREF")
                            {
                                plan.SkippedOffsets.Add(ins[index++].Offset);
                                plan.SkippedOffsets.Add(ins[index++].Offset);
                                plan.SkippedOffsets.Add(ins[index++].Offset);
                                continue;
                            }
                            break;
                        }
                    }
                    break;
                }
                caseIndex = mismatchIndex;
            }
            if (plan.HasFinally && plan.Cases.Count == 0)
            {
                int inlineFinallyIndex = IndexOfOffset(plan.FinallyStartOffset);
                int finallyHandlerIndex = IndexOfOffset(plan.FinallyHandlerOffset);
                int handlerBodyEnd = finallyHandlerIndex + 1;
                while (handlerBodyEnd < ins.Count && ins[handlerBodyEnd].Name != "RERAISE")
                    handlerBodyEnd++;
                bool handlerInsideLoop = finallyHandlerIndex >= 0 &&
                    ins.Take(finallyHandlerIndex).Any(instruction =>
                        instruction.Name == "FOR_ITER" && instruction.Target > ins[finallyHandlerIndex].Offset);
                if (inlineFinallyIndex >= protectedEndIndex && finallyHandlerIndex > inlineFinallyIndex &&
                    handlerBodyEnd < ins.Count && handlerInsideLoop)
                {
                    int finallyLine = SourceLine(inlineFinallyIndex);
                    for (int index = protectedEndIndex; index < finallyHandlerIndex; index++)
                    {
                        string name = ins[index].Name;
                        bool returnCleanup = IsReturnCleanup(index, inlineFinallyIndex, finallyHandlerIndex) ||
                            name is "JUMP_BACKWARD" or "JUMP_BACKWARD_NO_INTERRUPT";
                        if (SourceLine(index) == finallyLine && !returnCleanup)
                            plan.SkippedOffsets.Add(ins[index].Offset);
                    }
                    for (int index = finallyHandlerIndex + 1; index < handlerBodyEnd; index++)
                        plan.SkippedOffsets.Remove(ins[index].Offset);
                    plan.TryEndOffset = ins[finallyHandlerIndex + 1].Offset;
                    plan.FinallyStartOffset = plan.TryEndOffset;
                    plan.FinallyEndOffset = ins[handlerBodyEnd].Offset;
                }
                else if (inlineFinallyIndex >= protectedEndIndex && finallyHandlerIndex > inlineFinallyIndex &&
                    handlerBodyEnd < ins.Count && !handlerInsideLoop &&
                    ins.Take(inlineFinallyIndex).Any(instruction =>
                        instruction.Name == "FOR_ITER" && instruction.Target > ins[inlineFinallyIndex].Offset))
                {
                    int finallyLine = SourceLine(inlineFinallyIndex);
                    int continuationIndex = -1;
                    for (int index = inlineFinallyIndex; index < finallyHandlerIndex; index++)
                    {
                        string name = ins[index].Name;
                        bool controlCleanup = IsReturnCleanup(index, inlineFinallyIndex, finallyHandlerIndex) ||
                            name is "JUMP_BACKWARD" or "JUMP_BACKWARD_NO_INTERRUPT";
                        if (SourceLine(index) == finallyLine)
                        {
                            if (controlCleanup)
                                plan.PreservedOffsets.Add(ins[index].Offset);
                            else
                                plan.SkippedOffsets.Add(ins[index].Offset);
                        }
                        if (SourceLine(index) == finallyLine &&
                            name is "JUMP_BACKWARD" or "JUMP_BACKWARD_NO_INTERRUPT")
                            continuationIndex = index;
                    }
                    if (continuationIndex > inlineFinallyIndex &&
                        continuationIndex + 1 < finallyHandlerIndex)
                    {
                        int continueMarker = Enumerable.Range(inlineFinallyIndex, continuationIndex - inlineFinallyIndex)
                            .LastOrDefault(index => ins[index].Name == "NOP" &&
                                SourceLine(index) > 0 && SourceLine(index) != finallyLine, -1);
                        if (continueMarker >= 0)
                            plan.ExplicitContinueOffsets.Add(ins[continueMarker].Offset);
                        plan.TryEndOffset = ins[continuationIndex + 1].Offset;
                        plan.FinallyStartOffset = plan.TryEndOffset;
                        plan.FinallyBodyStartIndex = finallyHandlerIndex + 1;
                        plan.FinallyBodyEndIndex = handlerBodyEnd;
                        plan.EmitFinallyBodyFromHandler = true;
                    }
                }
            }
            bool isNestedCleanupContinuation = plan.Cases.Count == 0 &&
                entries.Any(entry => entry.End * 2 == plan.StartOffset && entry.Target * 2 != plan.HandlerOffset);
            if (!isNestedCleanupContinuation && (plan.Cases.Count > 0 || plan.HasFinally)) plans.Add(plan);
        }
        plans.AddRange(BuildExceptStarPlans());
        return plans;
    }

    List<SimpleTryPlan> BuildLegacyExceptPlans()
    {
        var plans = new List<SimpleTryPlan>();
        if (t.Minor is < 8 or > 10) return plans;

        var locations = LineTables.Decode(co, co.Code.Data.Length / 2);
        int SourceLine(int index)
        {
            int unit = ins[index].Offset / 2;
            return unit >= 0 && unit < locations.Length ? locations[unit].Line : -1;
        }

        foreach (var (setup, setupIndex) in ins.Select((instruction, index) => (instruction, index))
                     .Where(item => item.instruction.Name == "SETUP_FINALLY" &&
                         item.instruction.Target is int target && target > item.instruction.Offset))
        {
            int handlerOffset = setup.Target.Value;
            int handlerIndex = IndexOfOffset(handlerOffset);
            if (handlerIndex <= setupIndex + 1 || ins[handlerIndex].Name != "DUP_TOP") continue;

            var cases = new List<ExceptCase>();
            int caseIndex = handlerIndex, lastMismatchOffset = -1, maxHandlerLine = -1;
            while (caseIndex < ins.Count)
            {
                var exceptionCase = ParseLegacyExceptCase(caseIndex);
                if (exceptionCase == null) break;
                cases.Add(exceptionCase);
                lastMismatchOffset = exceptionCase.MismatchOffset;
                int bodyStart = IndexOfOffset(exceptionCase.BodyOffset);
                int bodyEnd = IndexOfOffset(exceptionCase.BodyEndOffset);
                if (bodyStart >= 0 && bodyEnd >= bodyStart)
                    for (int index = bodyStart; index < bodyEnd; index++)
                        maxHandlerLine = Math.Max(maxHandlerLine, SourceLine(index));
                int nextCase = IndexOfOffset(exceptionCase.MismatchOffset);
                if (nextCase < 0 || ins[nextCase].Name != "DUP_TOP") break;
                caseIndex = nextCase;
            }
            if (cases.Count == 0 || lastMismatchOffset < 0 || maxHandlerLine < 0) continue;

            int parentFinallyOffset = ins.Select((instruction, index) => (instruction, index))
                .Where(item => item.index < setupIndex && item.instruction.Name == "SETUP_FINALLY" &&
                    item.instruction.Target is int target && target > handlerOffset)
                .Select(item => item.instruction.Target.Value)
                .DefaultIfEmpty(-1)
                .Min();
            int afterCasesIndex = IndexOfOffset(lastMismatchOffset);
            if (afterCasesIndex < 0) continue;
            int elseStartIndex = -1;
            if (parentFinallyOffset > handlerOffset)
            {
                for (int index = afterCasesIndex; index < ins.Count &&
                     ins[index].Offset < parentFinallyOffset; index++)
                {
                    if (SourceLine(index) > maxHandlerLine &&
                        ins[index].Name is not ("RERAISE" or "END_FINALLY" or "POP_EXCEPT" or "POP_TOP"))
                    {
                        elseStartIndex = index;
                        break;
                    }
                }
            }

            var plan = new SimpleTryPlan
            {
                StartOffset = ins[setupIndex + 1].Offset,
                TryEndOffset = handlerOffset,
                HandlerOffset = handlerOffset,
                Cases = cases,
            };
            foreach (var (instruction, _) in ins.Select((instruction, index) => (instruction, index))
                         .Where(item => item.instruction.Name == "SETUP_FINALLY" &&
                             item.instruction.Target == handlerOffset))
                plan.SkippedOffsets.Add(instruction.Offset);

            if (elseStartIndex >= 0)
            {
                int returnIndex = -1;
                for (int index = elseStartIndex; index < ins.Count &&
                     (parentFinallyOffset < 0 || ins[index].Offset < parentFinallyOffset); index++)
                    if (ins[index].Name is "RETURN_VALUE" or "RETURN_CONST")
                    {
                        returnIndex = index;
                        break;
                    }
                if (returnIndex >= 0)
                {
                    plan.HasElse = true;
                    plan.ElseEndOffset = returnIndex + 1 < ins.Count
                        ? ins[returnIndex + 1].Offset
                        : co.Code.Data.Length;
                }
            }
            int skippedEndIndex = elseStartIndex >= 0 ? elseStartIndex : afterCasesIndex + 1;
            for (int index = handlerIndex; index < skippedEndIndex; index++)
                plan.SkippedOffsets.Add(ins[index].Offset);
            plans.Add(plan);
        }
        return plans;
    }

    List<SimpleTryPlan> BuildLegacyFinallyPlans()
    {
        var plans = new List<SimpleTryPlan>();
        if (t.Minor is < 8 or > 10) return plans;

        var locations = LineTables.Decode(co, co.Code.Data.Length / 2);
        int SourceLine(int index)
        {
            int unit = ins[index].Offset / 2;
            return unit >= 0 && unit < locations.Length ? locations[unit].Line : -1;
        }

        var setups = ins.Select((instruction, index) => (instruction, index))
            .Where(item => item.instruction.Name == "SETUP_FINALLY" &&
                item.instruction.Target is int target && target > item.instruction.Offset)
            .GroupBy(item => item.instruction.Target.Value);
        foreach (var setupGroup in setups)
        {
            if (setupGroup.Count() != 1) continue;
            var (setup, setupIndex) = setupGroup.Single();
            int handlerOffset = setup.Target.Value;
            int handlerIndex = IndexOfOffset(handlerOffset);
            if (handlerIndex <= setupIndex + 1) continue;
            if (ins[handlerIndex].Name is "END_ASYNC_FOR" or "END_FINALLY" or "POP_FINALLY" or
                "WITH_CLEANUP_START" or "WITH_EXCEPT_START" or "GET_AWAITABLE" or "YIELD_FROM" or "RERAISE")
                continue;

            int handlerEndIndex = -1;
            for (int index = handlerIndex; index < ins.Count; index++)
            {
                if (ins[index].Name is "END_FINALLY" or "RERAISE")
                {
                    handlerEndIndex = index;
                    break;
                }
                if (ins[index].Name is "SETUP_FINALLY" or "RETURN_VALUE" or "RETURN_CONST")
                    break;
            }
            if (handlerEndIndex <= handlerIndex ||
                ins.Skip(handlerIndex).Take(handlerEndIndex - handlerIndex)
                    .Any(instruction => instruction.Name is "COMPARE_OP" or "JUMP_IF_NOT_EXC_MATCH" or
                        "CHECK_EXC_MATCH" or "WITH_EXCEPT_START"))
                continue;
            bool exceptionNameCleanup = ins[handlerIndex].Name is "LOAD_CONST" or "LOAD_COMMON_CONSTANT" &&
                handlerIndex + 3 == handlerEndIndex &&
                ins[handlerIndex + 1].Name is "STORE_FAST" or "STORE_DEREF" &&
                ins[handlerIndex + 2].Name is "DELETE_FAST" or "DELETE_DEREF";
            if (exceptionNameCleanup) continue;

            var finallyLines = Enumerable.Range(handlerIndex, handlerEndIndex - handlerIndex)
                .Select(SourceLine).Where(line => line > 0).ToHashSet();
            if (finallyLines.Count == 0) continue;
            int bodyStartIndex = setupIndex + 1;

            var plan = new SimpleTryPlan
            {
                StartOffset = ins[bodyStartIndex].Offset,
                TryEndOffset = handlerOffset,
                FinallyStartOffset = handlerOffset,
                FinallyEndOffset = handlerEndIndex + 1 < ins.Count
                    ? ins[handlerEndIndex + 1].Offset
                    : co.Code.Data.Length,
                FinallyHandlerOffset = handlerOffset,
                HandlerOffset = handlerOffset,
                HasFinally = true,
            };
            foreach (var (instruction, index) in setupGroup)
                plan.SkippedOffsets.Add(instruction.Offset);

            for (int index = bodyStartIndex; index < handlerIndex; index++)
            {
                string name = ins[index].Name;
                if (finallyLines.Contains(SourceLine(index)) &&
                    name is not ("FOR_ITER" or "RETURN_VALUE" or "RETURN_CONST" or "RAISE_VARARGS"))
                    plan.SkippedOffsets.Add(ins[index].Offset);

                if (name == "CALL_FINALLY" && ins[index].Target == handlerOffset)
                {
                    plan.SkippedOffsets.Add(ins[index].Offset);
                    for (int cleanup = index + 1; cleanup < handlerIndex; cleanup++)
                    {
                        string cleanupName = ins[cleanup].Name;
                        if (cleanupName is "ROT_TWO" or "ROT_THREE" or "POP_TOP" or "SWAP")
                            plan.SkippedOffsets.Add(ins[cleanup].Offset);
                        else
                            break;
                    }
                }
                if (name == "BEGIN_FINALLY")
                    plan.SkippedOffsets.Add(ins[index].Offset);
            }
            for (int index = handlerEndIndex; index < ins.Count &&
                 ins[index].Name is "END_FINALLY" or "RERAISE" or "POP_FINALLY"; index++)
                plan.SkippedOffsets.Add(ins[index].Offset);
            int afterHandlerIndex = handlerEndIndex + 1;
            if (afterHandlerIndex < ins.Count &&
                ins[afterHandlerIndex].Name.StartsWith("JUMP", StringComparison.Ordinal) &&
                ins[afterHandlerIndex].Target is int continuation && continuation <= setup.Offset)
                plan.SkippedOffsets.Add(ins[afterHandlerIndex].Offset);

            plans.Add(plan);
        }
        return plans;
    }

    List<SimpleTryPlan> BuildExceptStarPlans()
    {
        var plans = new List<SimpleTryPlan>();
        if (t.Minor < 11 || co.ExceptionTable.Length == 0) return plans;

        var entries = LineTables.DecodeExc(co.ExceptionTable);
        var locations = LineTables.Decode(co, co.Code.Data.Length / 2);
        int SourceLine(int index)
        {
            int unit = ins[index].Offset / 2;
            return unit >= 0 && unit < locations.Length ? locations[unit].Line : -1;
        }

        var usedHandlers = new HashSet<int>();
        for (int firstCheck = 0; firstCheck < ins.Count; firstCheck++)
        {
            if (ins[firstCheck].Name != "CHECK_EG_MATCH") continue;
            int handlerIndex = firstCheck;
            while (handlerIndex >= 0 && ins[handlerIndex].Name != "PUSH_EXC_INFO")
                handlerIndex--;
            if (handlerIndex < 0 || !usedHandlers.Add(ins[handlerIndex].Offset)) continue;

            var protectedEntry = entries
                .Where(entry => entry.Target * 2 == ins[handlerIndex].Offset &&
                    entry.End * 2 == ins[handlerIndex].Offset && entry.Start * 2 < entry.End * 2)
                .OrderBy(entry => entry.Start)
                .FirstOrDefault();
            if (protectedEntry == default) continue;

            var cases = new List<ExceptCase>();
            int maxCaseLine = -1;
            int cursor = handlerIndex;
            while (cursor < ins.Count)
            {
                int checkIndex = cursor;
                while (checkIndex < ins.Count && ins[checkIndex].Name != "CHECK_EG_MATCH" &&
                    ins[checkIndex].Name is not ("PREP_RERAISE_STAR" or "CALL_INTRINSIC_2"))
                    checkIndex++;
                if (checkIndex >= ins.Count ||
                    ins[checkIndex].Name is "PREP_RERAISE_STAR" or "CALL_INTRINSIC_2")
                    break;

                string exceptionType = ExceptionTypeText(handlerIndex, checkIndex);
                if (exceptionType == null) break;
                int branchIndex = checkIndex + 1;
                while (branchIndex < ins.Count && ins[branchIndex].Name is "COPY" or "NOT_TAKEN")
                    branchIndex++;
                if (branchIndex >= ins.Count ||
                    !ins[branchIndex].Name.StartsWith("POP_JUMP", StringComparison.Ordinal) ||
                    !ins[branchIndex].Name.EndsWith("IF_NONE", StringComparison.Ordinal) ||
                    ins[branchIndex].Target is not int missOffset)
                    break;

                int bodyIndex = branchIndex + 1;
                if (bodyIndex < ins.Count && ins[bodyIndex].Name == "NOT_TAKEN") bodyIndex++;
                string binding = null;
                if (bodyIndex < ins.Count && ins[bodyIndex].Name is "STORE_FAST" or "STORE_NAME" or "STORE_DEREF")
                {
                    binding = Operand(ins[bodyIndex]);
                    bodyIndex++;
                }
                else if (bodyIndex < ins.Count && ins[bodyIndex].Name == "POP_TOP")
                    bodyIndex++;
                if (bodyIndex >= ins.Count) break;

                int bodyEndIndex = -1;
                for (int index = bodyIndex; index < ins.Count; index++)
                {
                    bool loadsNone = ins[index].Name == "LOAD_COMMON_CONSTANT" &&
                        Operand(ins[index]) == "None" ||
                        ins[index].Name == "LOAD_CONST" && ins[index].RefIndex >= 0 &&
                        ins[index].RefIndex < co.Consts.Count && co.Consts[ins[index].RefIndex] is PyNone;
                    if (binding != null && loadsNone &&
                        index + 2 < ins.Count && ins[index + 1].Name is "STORE_FAST" or "STORE_NAME" or "STORE_DEREF" &&
                        Operand(ins[index + 1]) == binding &&
                        ins[index + 2].Name is "DELETE_FAST" or "DELETE_NAME" or "DELETE_DEREF")
                    {
                        bodyEndIndex = index;
                        break;
                    }
                    if (ins[index].Name is "LIST_APPEND" or "PREP_RERAISE_STAR" ||
                        ins[index].Name == "CALL_INTRINSIC_2" &&
                        Operand(ins[index]).Contains("PREP_RERAISE_STAR", StringComparison.Ordinal) ||
                        ins[index].Name.StartsWith("JUMP", StringComparison.Ordinal) &&
                        ins[index].Target is int target && target > ins[index].Offset ||
                        ins[index].Name is "RAISE_VARARGS" or "RETURN_VALUE" or "RETURN_CONST")
                    {
                        bodyEndIndex = ins[index].Name is "RAISE_VARARGS" or "RETURN_VALUE" or "RETURN_CONST"
                            ? index + 1
                            : index;
                        break;
                    }
                    if (ins[index].Name is "CHECK_EG_MATCH" or "RERAISE" or "POP_EXCEPT")
                        break;
                }
                if (bodyEndIndex < bodyIndex) break;

                var exceptionCase = new ExceptCase
                {
                    HeaderOffset = ins[handlerIndex].Offset,
                    BodyOffset = ins[bodyIndex].Offset,
                    BodyEndOffset = bodyEndIndex < ins.Count ? ins[bodyEndIndex].Offset : co.Code.Data.Length,
                    ExceptionType = exceptionType,
                    Name = binding,
                    MismatchOffset = missOffset,
                    IsStar = true,
                };
                cases.Add(exceptionCase);
                for (int index = bodyIndex; index < bodyEndIndex; index++)
                {
                    maxCaseLine = Math.Max(maxCaseLine, SourceLine(index));
                }
                cursor = Math.Max(checkIndex + 1, bodyEndIndex);
            }
            if (cases.Count == 0 || maxCaseLine < 0) continue;

            int prepIndex = -1;
            for (int index = cursor; index < ins.Count; index++)
            {
                if (ins[index].Name == "PREP_RERAISE_STAR" ||
                    ins[index].Name == "CALL_INTRINSIC_2" &&
                    Operand(ins[index]).Contains("PREP_RERAISE_STAR", StringComparison.Ordinal))
                {
                    prepIndex = index;
                    break;
                }
            }
            if (prepIndex < 0) continue;

            int afterHandlerIndex = -1;
            for (int index = prepIndex + 1; index < ins.Count; index++)
            {
                string name = ins[index].Name;
                if (SourceLine(index) > maxCaseLine &&
                    name is not ("COPY" or "SWAP" or "POP_TOP" or "POP_EXCEPT" or "RERAISE" or "NOT_TAKEN"))
                {
                    afterHandlerIndex = index;
                    break;
                }
            }
            if (afterHandlerIndex <= prepIndex) continue;

            var plan = new SimpleTryPlan
            {
                StartOffset = protectedEntry.Start * 2,
                TryEndOffset = ins[handlerIndex].Offset,
                HandlerOffset = ins[handlerIndex].Offset,
                Cases = cases,
            };
            for (int index = handlerIndex; index < afterHandlerIndex; index++)
                plan.SkippedOffsets.Add(ins[index].Offset);
            plans.Add(plan);
            firstCheck = afterHandlerIndex - 1;
        }
        return plans;
    }

    ExceptCase ParseLegacyExceptCase(int headerIndex)
    {
        int checkIndex = -1;
        bool isCompareMatch = false;
        for (int index = headerIndex; index < ins.Count; index++)
        {
            if (ins[index].Name == "JUMP_IF_NOT_EXC_MATCH")
            {
                checkIndex = index;
                break;
            }
            if (ins[index].Name == "COMPARE_OP" &&
                Operand(ins[index]).Contains("exception match", StringComparison.Ordinal))
            {
                checkIndex = index;
                isCompareMatch = true;
                break;
            }
            if (ins[index].Name is "END_FINALLY" or "RERAISE" or "POP_EXCEPT")
                return null;
        }
        if (checkIndex < 0) return null;
        string exceptionType = ExceptionTypeText(headerIndex, checkIndex);
        if (exceptionType == null) return null;

        int branchIndex = checkIndex + (isCompareMatch ? 1 : 0);
        while (branchIndex < ins.Count && ins[branchIndex].Name == "NOT_TAKEN")
            branchIndex++;
        if (branchIndex >= ins.Count || ins[branchIndex].Target is not int mismatchOffset ||
            !(isCompareMatch
                ? ins[branchIndex].Name.StartsWith("POP_JUMP", StringComparison.Ordinal) &&
                    ins[branchIndex].Name.EndsWith("IF_FALSE", StringComparison.Ordinal)
                : ins[branchIndex].Name == "JUMP_IF_NOT_EXC_MATCH"))
            return null;

        int bodyIndex = branchIndex + 1;
        string binding = null;
        while (bodyIndex < ins.Count && ins[bodyIndex].Offset < mismatchOffset)
        {
            if (ins[bodyIndex].Name == "POP_TOP")
            {
                bodyIndex++;
                continue;
            }
            if (ins[bodyIndex].Name is "STORE_FAST" or "STORE_NAME" or "STORE_DEREF")
            {
                binding = Operand(ins[bodyIndex++]);
                continue;
            }
            if (ins[bodyIndex].Name == "SETUP_FINALLY")
            {
                bodyIndex++;
                continue;
            }
            break;
        }
        int mismatchIndex = IndexOfOffset(mismatchOffset);
        if (mismatchIndex < 0 || bodyIndex > mismatchIndex) return null;

        int bodyEndIndex = mismatchIndex;
        for (int index = bodyIndex; index < mismatchIndex; index++)
        {
            if (ins[index].Name is "RAISE_VARARGS" or "RETURN_VALUE" or "RETURN_CONST")
            {
                bodyEndIndex = index + 1;
                break;
            }
            if (ins[index].Name == "POP_EXCEPT" ||
                ins[index].Name.StartsWith("JUMP", StringComparison.Ordinal) &&
                ins[index].Target is int target && target > mismatchOffset)
            {
                bodyEndIndex = index;
                break;
            }
        }
        return new ExceptCase
        {
            HeaderOffset = ins[headerIndex].Offset,
            BodyOffset = bodyIndex < ins.Count ? ins[bodyIndex].Offset : co.Code.Data.Length,
            BodyEndOffset = bodyEndIndex < ins.Count ? ins[bodyEndIndex].Offset : co.Code.Data.Length,
            ExceptionType = exceptionType,
            Name = binding,
            MismatchOffset = mismatchOffset,
        };
    }

    ExceptCase ParseExceptCase(int headerIndex)
    {
        int checkIndex = -1;
        for (int index = headerIndex; index < ins.Count; index++)
        {
            if (ins[index].Name == "CHECK_EXC_MATCH") { checkIndex = index; break; }
            if (ins[index].Name is "RERAISE" or "POP_EXCEPT") return null;
        }
        if (checkIndex < 0) return null;
        string exceptionType = ExceptionTypeText(headerIndex, checkIndex);
        if (exceptionType == null) return null;

        int branchIndex = checkIndex + 1;
        while (branchIndex < ins.Count && ins[branchIndex].Name == "NOT_TAKEN") branchIndex++;
        if (branchIndex >= ins.Count || !ins[branchIndex].Name.StartsWith("POP_JUMP", StringComparison.Ordinal) ||
            !ins[branchIndex].Name.EndsWith("IF_FALSE", StringComparison.Ordinal) ||
            ins[branchIndex].Target is not int mismatchOffset) return null;
        int bodyIndex = branchIndex + 1;
        if (bodyIndex < ins.Count && ins[bodyIndex].Name == "NOT_TAKEN") bodyIndex++;
        string name = null;
        if (bodyIndex < ins.Count && ins[bodyIndex].Name is "STORE_FAST" or "STORE_NAME" or "STORE_DEREF")
        {
            name = Operand(ins[bodyIndex]);
            bodyIndex++;
        }
        else if (bodyIndex < ins.Count && ins[bodyIndex].Name == "POP_TOP")
            bodyIndex++;

        int bodyEndIndex = -1;
        for (int index = bodyIndex; index < ins.Count; index++)
        {
            if (ins[index].Offset >= mismatchOffset) break;
            if (ins[index].Name == "POP_EXCEPT") { bodyEndIndex = index; break; }
            if (ins[index].Name is "RAISE_VARARGS" or "RETURN_VALUE" or "RETURN_CONST")
            {
                bodyEndIndex = index + 1;
                break;
            }
        }
        if (bodyIndex >= ins.Count || bodyEndIndex < 0) return null;
        if (ins.Skip(bodyIndex).Take(bodyEndIndex - bodyIndex)
            .Any(instruction => instruction.Target.HasValue || instruction.Name.StartsWith("POP_JUMP", StringComparison.Ordinal)))
            return null;
        return new ExceptCase
        {
            HeaderOffset = ins[headerIndex].Offset,
            BodyOffset = ins[bodyIndex].Offset,
            BodyEndOffset = bodyEndIndex < ins.Count ? ins[bodyEndIndex].Offset : co.Code.Data.Length,
            ExceptionType = exceptionType,
            Name = name,
            MismatchOffset = mismatchOffset,
        };
    }

    string ExceptionTypeText(int startIndex, int checkIndex)
    {
        int tupleIndex = -1;
        for (int index = startIndex; index < checkIndex; index++)
            if (ins[index].Name == "BUILD_TUPLE") tupleIndex = index;
        if (tupleIndex >= 0)
        {
            int count = ins[tupleIndex].Arg;
            var names = ins.Skip(Math.Max(startIndex, tupleIndex - count))
                .Take(Math.Min(count, tupleIndex - startIndex))
                .Select(ExceptionName).ToList();
            if (names.Count != count || names.Any(name => name == null)) return null;
            return "(" + string.Join(", ", names) + (count == 1 ? "," : "") + ")";
        }
        for (int index = checkIndex - 1; index >= startIndex; index--)
        {
            string name = ExceptionName(ins[index]);
            if (name != null) return name;
        }
        return null;
    }

    string ExceptionName(Instruction instruction) =>
        instruction.Name == "LOAD_GLOBAL" || instruction.Name == "LOAD_NAME"
            ? NameOf(instruction)
            : instruction.Name is "LOAD_FAST" or "LOAD_FAST_CHECK" or "LOAD_DEREF"
                ? Operand(instruction)
                : null;

    void EmitScopeDeclarations()
    {
        if (compMode || co.IsModule) return;
        var globals = ins.Where(i => i.Name is "STORE_GLOBAL" or "DELETE_GLOBAL")
            .Select(NameOf).Distinct(StringComparer.Ordinal).ToList();
        var freeVars = new HashSet<string>(co.FreeVars, StringComparer.Ordinal);
        var nonlocals = ins.Where(i => i.Name is "STORE_DEREF" or "DELETE_DEREF")
            .Select(Operand).Where(freeVars.Contains).Distinct(StringComparer.Ordinal).ToList();
        if (globals.Count > 0) Emit("global " + string.Join(", ", globals));
        if (nonlocals.Count > 0) Emit("nonlocal " + string.Join(", ", nonlocals));
    }

    void CloseBlocks(int off, bool stopAfterTry = false)
    {
        while (open.Count > 0 && open[^1].End <= off)
        {
            var b = open[^1]; open.RemoveAt(open.Count - 1);
            if (b.Kind == "for" && b.For != null)
            {
                int iteratorIndex = stack.FindLastIndex(value =>
                    value.Kind == "for_iterator" && ReferenceEquals(value.For, b.For));
                if (iteratorIndex >= 0) stack.RemoveAt(iteratorIndex);
            }
            if (b.Kind == "with" && stack.Count > 0 &&
                stack[^1].Kind is not ("with_exit" or "mark" or "underflow"))
            {
                var returnValue = Pop();
                Emit(returnValue.Const is PyNone ? "return" : "return " + Strip(returnValue.S));
                suppressWithReturn = true;
            }
            if (lines.Count - 1 == b.HeaderIdx) lines.Add(Sp(b.Indent + 1) + "pass");
            ind = b.Indent;
            if (b.Kind is "if" or "for" && b.ElseTo > off)
            {
                Emit("else:");
                open.Add(new OpenBlock { Kind = "else", End = b.ElseTo, Indent = ind, HeaderIdx = lines.Count - 1 });
                ind++;
            }
            if (stopAfterTry && b.Kind == "try") break;
        }
    }

    void ResolvePending(int off)
    {
        int outerOrIndex = pend.FindLastIndex(item => item.Target == off && item.Op == "or");
        int deferredAndIndex = pend.FindLastIndex(item => item.Op == "and" && item.Target < off);
        if (outerOrIndex >= 0 && deferredAndIndex >= 0 && deferredAndIndex < outerOrIndex)
        {
            var andPending = pend[deferredAndIndex];
            var orPending = pend[outerOrIndex];
            var fallback = Pop();
            var andExpression = new Ex(
                $"{W(andPending.Left, 3)} and {W(orPending.Left, 4)}",
                3);
            Push(new Ex($"{W(andExpression, 2)} or {W(fallback, 3)}", 2));
            pend.RemoveAt(outerOrIndex);
            pend.RemoveAt(deferredAndIndex);
            if (StartsWithBooleanCleanup(off)) skipPop = true;
        }

        for (int k = pend.Count - 1; k >= 0; k--)
        {
            if (pend[k].Target != off) continue;
            if (pend[k].Op == "and" && pend.Any(item => item.Op == "or" && item.Target > off))
                continue;
            var pb = pend[k]; pend.RemoveAt(k);
            var right = Pop();
            if (pb.Op == "and" && pb.Left.CompareOperands is { Count: > 1 } leftOperands &&
                pb.Left.CompareOperators is { } leftOperators &&
                right.CompareOperands is { Count: > 1 } rightOperands &&
                right.CompareOperators is { } rightOperators &&
                ReferenceEquals(leftOperands[^1], rightOperands[0]))
            {
                var operands = leftOperands.Concat(rightOperands.Skip(1)).ToList();
                var operators = leftOperators.Concat(rightOperators).ToList();
                var expression = new StringBuilder(operands[0].S);
                for (int index = 0; index < operators.Count; index++)
                    expression.Append(' ').Append(operators[index]).Append(' ').Append(operands[index + 1].S);
                Push(new Ex(expression.ToString(), 5)
                {
                    CompareOperands = operands,
                    CompareOperators = operators,
                });
                if (StartsWithBooleanCleanup(off)) skipPop = true;
                continue;
            }
            int p = pb.Op == "and" ? 3 : 2;
            Push(new Ex($"{W(pb.Left, p)} {pb.Op} {W(right, p + 1)}", p));
            if (StartsWithBooleanCleanup(off)) skipPop = true;
        }
    }

    static bool IsUnconditionalTerminator(string line) =>
        line == "return" || line.StartsWith("return ", StringComparison.Ordinal) ||
        line == "raise" || line.StartsWith("raise ", StringComparison.Ordinal) ||
        line == "break" || line == "continue";

    bool StartsWithBooleanCleanup(int offset)
    {
        int index = IndexOfOffset(offset);
        while (index >= 0 && index < ins.Count && ins[index].Name is "NOT_TAKEN" or "SWAP")
            index++;
        return index >= 0 && index < ins.Count && ins[index].Name == "POP_TOP";
    }

    bool IsBooleanReturnJoin(int branchIndex, int fallbackOffset)
    {
        int fallbackIndex = IndexOfOffset(fallbackOffset);
        if (fallbackIndex < 0 || fallbackIndex + 1 >= ins.Count) return false;
        bool returnsNone = ins[fallbackIndex].Name == "LOAD_CONST" &&
            ins[fallbackIndex].RefIndex >= 0 &&
            ins[fallbackIndex].RefIndex < co.Consts.Count &&
            co.Consts[ins[fallbackIndex].RefIndex] is PyNone &&
            ins[fallbackIndex + 1].Name is "RETURN_VALUE" or "RETURN_CONST";
        if (!returnsNone) return false;
        for (int index = branchIndex + 1; index < fallbackIndex; index++)
        {
            if (ins[index].Name != "JUMP_IF_TRUE_OR_POP" ||
                ins[index].Target is not int joinOffset) continue;
            int joinIndex = IndexOfOffset(joinOffset);
            if (joinIndex >= 0 && ins[joinIndex].Name is "RETURN_VALUE" or "RETURN_CONST")
                return true;
        }
        return false;
    }

    bool IsFoldedBreakReturn(int index, int offset)
    {
        if (ins[index].Name != "RETURN_VALUE" || index < 3 ||
            ins[index - 1].Name is not ("LOAD_FAST" or "LOAD_FAST_BORROW" or "LOAD_FAST_CHECK" or
                "LOAD_DEREF" or "LOAD_GLOBAL" or "LOAD_NAME") ||
            ins[index - 2].Name != "POP_TOP" ||
            !open.Any(block => block.Kind == "for" && block.End > offset))
            return false;

        int cleanupOffset = ins[index - 2].Offset;
        for (int branchIndex = index - 3; branchIndex >= Math.Max(0, index - 12); branchIndex--)
            if (ins[branchIndex].Name.StartsWith("POP_JUMP", StringComparison.Ordinal) &&
                ins[branchIndex].Target is int target &&
                (target == cleanupOffset || target > offset))
                return true;
        return false;
    }

    bool IsLoopIteratorCleanupPath(int index, int offset)
    {
        if (stack.Count == 0 || stack[^1].Kind != "for_iterator" || stack[^1].For == null ||
            !open.Any(block => block.Kind == "for" && ReferenceEquals(block.For, stack[^1].For) && block.End > offset))
            return false;

        int next = index + 1;
        if (next < ins.Count && ins[next].Name.StartsWith("JUMP", StringComparison.Ordinal) &&
            ins[next].Target is int jumpTarget &&
            open.Any(block => block.Kind == "for" && ReferenceEquals(block.For, stack[^1].For) &&
                jumpTarget >= block.End))
            return true;

        if (next + 1 < ins.Count && ins[next].Name is
                ("LOAD_FAST" or "LOAD_FAST_BORROW" or "LOAD_FAST_CHECK" or "LOAD_DEREF" or "LOAD_GLOBAL" or "LOAD_NAME" or "LOAD_CONST") &&
            ins[next + 1].Name == "RETURN_VALUE")
            return true;

        for (int cursor = next; cursor < ins.Count && cursor <= index + 8; cursor++)
        {
            if (ins[cursor].Name is "RETURN_VALUE" or "RETURN_CONST") return true;
            if (ins[cursor].Name is not ("SWAP" or "POP_TOP" or "NOT_TAKEN")) return false;
        }
        return false;
    }

    void CaptureLoopIteratorMarkers()
    {
        iteratorMarkersToRestore ??= stack.Select((value, index) => (value, index))
            .Where(item => item.value.Kind == "for_iterator")
            .Select(item => (item.index, item.value))
            .ToList();
    }

    void RestoreLoopIteratorMarkers()
    {
        if (iteratorMarkersToRestore == null) return;
        foreach (var (index, marker) in iteratorMarkersToRestore)
            if (!stack.Contains(marker))
                stack.Insert(Math.Min(index, stack.Count), marker);
        iteratorMarkersToRestore = null;
    }

    void Step(int k, Instruction i, int off, int next)
    {
        string n = i.Name;
        bool wasCopy1 = afterCopy1;
        if (n != "TO_BOOL") afterCopy1 = false;
        bool last = k == ins.Count - 1;

        switch (n)
        {
            case "NOP": case "RESUME": case "PRECALL": case "MAKE_CELL": case "COPY_FREE_VARS": case "TO_BOOL": case "END_FOR": case "POP_ITER":
            case "GET_ITER": case "GET_AITER": case "END_SEND": case "CLEANUP_THROW": case "SETUP_ANNOTATIONS":
            case "RETURN_GENERATOR": case "GEN_START": case "ASYNC_GEN_WRAP": case "NOT_TAKEN":
            case "POP_BLOCK": case "SETUP_ASYNC_WITH":
            case "BEGIN_FINALLY": case "WITH_CLEANUP_FINISH": case "END_FINALLY": case "POP_FINALLY":
            case "PUSH_EXC_INFO": case "CHECK_EXC_MATCH": case "POP_EXCEPT":
                if (n is "GET_ITER" or "GET_AITER") { var it = Pop(); Push(it); }
                return;
            case "KW_NAMES":
                kwnames = i.RefIndex >= 0 && i.Arg < co.Consts.Count && co.Consts[i.Arg] is PyTuple kt ? kt.Items.Select(x => x is PyStr s ? s.Value : x.Repr()).ToList() : null;
                return;
        }

        if (n == "WITH_CLEANUP_START")
        {
            int exitIndex = stack.FindLastIndex(value => value.Kind == "with_exit");
            if (exitIndex >= 0) stack.RemoveAt(exitIndex);
            return;
        }

        if (n is "GET_AWAITABLE" or "GET_YIELD_FROM_ITER")
        {
            var value = Pop();
            if (n == "GET_AWAITABLE" && value.Kind == "with_exit")
            {
                Push(value);
                return;
            }
            Push(new Ex(value.S)
            {
                Kind = n == "GET_AWAITABLE"
                    ? value.Kind == "async_comp" ? "async_comp_awaitable" : "awaitable"
                    : "yield_iter",
                WithManager = value.WithManager,
                IsAsync = value.IsAsync,
            });
            return;
        }
        if (n == "SEND")
        {
            Pop();
            var receiver = Pop();
            if (receiver.Kind == "mark" && receiver.S == "NULL")
                receiver = Pop();
            if (receiver.Kind == "with_exit")
            {
                Push(receiver);
                if (i.Target is int exitTarget) skipToOffset = exitTarget;
                return;
            }
            if (receiver.Kind == "async_comp_awaitable")
            {
                Push(new Ex(Strip(receiver.S)));
                if (i.Target is int comprehensionTarget) skipToOffset = comprehensionTarget;
                return;
            }
            if (receiver.Kind == "awaitable" && receiver.WithManager != null)
            {
                Push(new Ex("<with-enter>") { Kind = "with_enter", WithManager = receiver.WithManager, IsAsync = true });
                if (i.Target is int awaitTarget) skipToOffset = awaitTarget;
                return;
            }
            bool isYieldFrom = receiver.Kind == "yield_iter" ||
                t.Minor >= 15 && (co.Flags & (0x80 | 0x200)) == 0;
            string value = isYieldFrom
                ? "yield from " + receiver.S
                : "await " + Strip(receiver.S);
            Push(new Ex("(" + value + ")") { Kind = isYieldFrom ? "yield_from" : "await" });
            if (i.Target is int target) skipToOffset = target;
            return;
        }
        if (n == "CALL_INTRINSIC_1" && Operand(i) == "INTRINSIC_IMPORT_STAR")
        {
            var module = Pop();
            Emit($"from {module.Imp?.Module ?? Strip(module.S)} import *");
            return;
        }
        if (n == "CALL_INTRINSIC_1" && Operand(i) == "INTRINSIC_ASYNC_GEN_WRAP") return;
        if (n == "CALL_INTRINSIC_1" && Operand(i) == "INTRINSIC_STOPITERATION_ERROR") return;
        if (n == "CALL_INTRINSIC_1" && Operand(i) == "INTRINSIC_UNARY_POSITIVE")
        {
            var value = Pop();
            Push(new Ex("+" + W(value, 12), 12));
            return;
        }
        if (n == "CALL_INTRINSIC_1" && Operand(i) is
            "INTRINSIC_TYPEVAR" or "INTRINSIC_TYPEVARTUPLE" or "INTRINSIC_PARAMSPEC")
        {
            var name = Pop();
            Push(new Ex(Strip(name.S)) { Kind = "type_param" });
            return;
        }
        if (n == "CALL_INTRINSIC_2" && Operand(i) == "INTRINSIC_TYPEVAR_WITH_BOUND")
        {
            Pop();
            var name = Pop();
            Push(new Ex(Strip(name.S)) { Kind = "type_param" });
            return;
        }
        if (n == "CALL_INTRINSIC_2" && Operand(i) == "INTRINSIC_SET_FUNCTION_TYPE_PARAMS")
        {
            var right = Pop();
            var left = Pop();
            var function = right.Func != null ? right : left;
            if (function.Func != null) GenericFunctionResult = function.Func;
            Push(function);
            return;
        }
        if (n == "RERAISE") return;

        if (n == "LOAD_CONST") { Push(ConstEx(i.RefIndex >= 0 && i.RefIndex < co.Consts.Count ? co.Consts[i.RefIndex] : null)); return; }
        if (n == "LOAD_SMALL_INT") { Push(new Ex(i.Arg.ToString()) { Const = new PyInt(i.Arg) }); return; }
        if (n == "LOAD_COMMON_CONSTANT")
        {
            Ex value = t.Minor >= 15 ? i.Arg switch
            {
                7 => ConstEx(PyNone.Instance),
                8 => ConstEx(new PyStr("")),
                9 => ConstEx(PyBool.True),
                10 => ConstEx(PyBool.False),
                11 => ConstEx(new PyInt(-1)),
                13 => ConstEx(new PyTuple()),
                _ => new Ex(Operand(i)),
            } : new Ex(Operand(i));
            Push(value);
            return;
        }
        if (n == "LOAD_ASSERTION_ERROR") { Push(new Ex("AssertionError")); return; }
        if (n == "LOAD_BUILD_CLASS") { Push(new Ex("__build_class__") { Kind = "build_class" }); return; }
        if (n == "PUSH_NULL") { Push(new Ex("NULL") { Kind = "mark" }); return; }
        if (n == "LOAD_GLOBAL")
        {
            var g = new Ex(NameOf(i));
            bool nul = i.Operand.Contains("NULL");
            if (nul && t.Minor < 13) Push(new Ex("NULL") { Kind = "mark" });
            Push(g);
            if (nul && t.Minor >= 13) Push(new Ex("NULL") { Kind = "mark" });
            return;
        }
        if (n is "LOAD_NAME" or "LOAD_FAST" or "LOAD_FAST_CHECK" or "LOAD_FAST_AND_CLEAR" or "LOAD_FAST_BORROW" or "LOAD_DEREF" or "LOAD_CLASSDEREF" or "LOAD_CLOSURE")
        {
            string nm = n == "LOAD_NAME" ? NameOf(i) : Operand(i);
            if (annotationMode && co.Name == "__annotate__" && n == "LOAD_DEREF" &&
                nm == "__classdict__")
            {
                Push(new Ex("__annotations__") { Kind = "class_annotations" });
                return;
            }
            if (n == "LOAD_FAST_AND_CLEAR")
            {
                compBuilder = true;
                BeginCompLocal(nm);
                Push(new Ex(nm) { Kind = "comp_backup" });
                return;
            }
            Push(new Ex(LocalName(nm))); return;
        }
        if (n is "LOAD_FROM_DICT_OR_GLOBALS" or "LOAD_FROM_DICT_OR_DEREF")
        {
            Pop();
            Push(new Ex(n.EndsWith("GLOBALS", StringComparison.Ordinal) ? NameOf(i) : Operand(i)));
            return;
        }
        if (n is "LOAD_FAST_LOAD_FAST" or "LOAD_FAST_BORROW_LOAD_FAST_BORROW")
        {
            var parts = Operand(i).Split(", ");
            foreach (var p in parts) Push(new Ex(LocalName(p)));
            return;
        }
        if (n is "LOAD_ATTR" or "LOAD_METHOD")
        {
            var o = Pop();
            bool method = n == "LOAD_METHOD" || (t.Minor >= 12 && i.Operand.Contains("NULL|self"));
            Push(new Ex(W(o, 20) + "." + NameOf(i)));
            if (method) Push(new Ex("SELF") { Kind = "mark" });
            return;
        }
        if (n == "LOAD_SUPER_ATTR")
        {
            Pop(); Pop(); Pop();
            Push(new Ex("super()." + NameOf(i)));
            if (i.Operand.Contains("NULL|self")) Push(new Ex("SELF") { Kind = "mark" });
            return;
        }
        if (n == "LOAD_SPECIAL")
        {
            var receiver = Pop();
            string special = Operand(i);
            string kind = special == "__enter__" ? "with_enter_callable"
                : special == "__aenter__" ? "async_with_enter_callable"
                : special is "__exit__" or "__aexit__" ? "with_exit_callable" : "";
            Push(new Ex(W(receiver, 20) + "." + special)
            {
                Kind = kind,
                WithManager = kind == "" ? null : receiver.S,
                IsAsync = special is "__aenter__" or "__aexit__",
            });
            Push(new Ex("SELF") { Kind = "mark" });
            return;
        }
        if (n == "LOAD_LOCALS" && co.IsClassBody)
        {
            Push(new Ex("<class locals>") { Kind = "class_locals" });
            return;
        }
        if (n is "BEFORE_WITH" or "BEFORE_ASYNC_WITH")
        {
            var manager = Pop();
            Push(new Ex(manager.S) { Kind = "with_exit" });
            Push(new Ex("<with-enter>")
            {
                Kind = "with_enter",
                WithManager = manager.S,
                IsAsync = n == "BEFORE_ASYNC_WITH",
            });
            return;
        }
        if (n == "SETUP_WITH")
        {
            var manager = Pop();
            Push(new Ex(manager.S) { Kind = "with_exit", WithManager = manager.S });
            Push(new Ex("<with-enter>") { Kind = "with_enter", WithManager = manager.S });
            return;
        }

        if (n is "STORE_NAME" or "STORE_GLOBAL") { Store(NameOf(i)); return; }
        if (n is "STORE_FAST" or "STORE_DEREF") { Store(n == "STORE_FAST" ? LocalName(Operand(i)) : Operand(i)); return; }
        if (n == "STORE_FAST_LOAD_FAST") { var ps = Operand(i).Split(", "); Store(LocalName(ps[0])); Push(new Ex(LocalName(ps[1]))); return; }
        if (n == "STORE_FAST_STORE_FAST") { var ps = Operand(i).Split(", "); Store(LocalName(ps[0])); Store(LocalName(ps[1])); return; }
        if (n == "STORE_ATTR") { var o = Pop(); Store(W(o, 20) + "." + NameOf(i)); return; }
        if (n == "STORE_SUBSCR")
        {
            var idx = Pop(); var o = Pop(); var value = Pop();
            if (annotationMode && o.Kind == "class_annotations" &&
                idx.Const is PyStr annotationName)
            {
                ClassAnnotations[annotationName.Value] = Strip(value.S);
                return;
            }
            Emit($"{W(o, 20)}[{Strip(idx.S)}] = {Strip(value.S)}");
            return;
        }
        if (n is "DELETE_NAME" or "DELETE_GLOBAL") { Emit("del " + NameOf(i)); return; }
        if (n is "DELETE_FAST" or "DELETE_DEREF") { Emit("del " + (n == "DELETE_FAST" ? LocalName(Operand(i)) : Operand(i))); return; }
        if (n == "DELETE_ATTR") { var o = Pop(); Emit($"del {W(o, 20)}.{NameOf(i)}"); return; }
        if (n == "DELETE_SUBSCR") { var o = Pop(); var idx = Pop(); Emit($"del {W(o, 20)}[{Strip(idx.S)}]"); return; }

        switch (n)
        {
            case "POP_TOP":
            {
                if (skipPop) { skipPop = false; return; }
                if (Peek().Kind == "for_iterator" && IsLoopIteratorCleanupPath(k, off))
                    CaptureLoopIteratorMarkers();
                var v = Pop();
                if (v.Kind is "import" or "for" or "for_iterator" or "unpack" or "mark" or "underflow" or "importfrom") return;
                if (v.Kind == "with_enter") { EmitWith(v, null); return; }
                if (v.Kind == "with_exit") return;
                if (v.Func != null || v.Cls != null) return;
                Emit(Strip(v.S));
                return;
            }
            case "DUP_TOP": Push(Peek()); return;
            case "DUP_TOP_TWO": { var a = Peek(1); var b = Peek(0); Push(a); Push(b); return; }
            case "COPY":
                Push(Peek(i.Arg - 1));
                if (i.Arg == 1) afterCopy1 = true;
                return;
            case "SWAP":
            {
                int d = i.Arg - 1;
                bool returnCleanup = t.Minor >= 15 && i.Arg == 3 && stack.Count == 2 &&
                    stack[0].Kind == "for_iterator" && k + 3 < ins.Count &&
                    ins[k + 1].Name == "POP_TOP" && ins[k + 2].Name == "POP_TOP" &&
                    ins[k + 3].Name is "RETURN_VALUE" or "RETURN_CONST";
                if (returnCleanup) stack.Insert(0, new Ex("<implicit loop state>") { Kind = "mark" });
                if (stack.Count > d)
                    (stack[^1], stack[^(d + 1)]) = (stack[^(d + 1)], stack[^1]);
                return;
            }
            case "ROT_TWO": { var a = Pop(); var b = Pop(); Push(a); Push(b); return; }
            case "ROT_THREE": { var a = Pop(); var b = Pop(); var c = Pop(); Push(a); Push(c); Push(b); return; }
            case "ROT_FOUR": { var a = Pop(); var b = Pop(); var c = Pop(); var d = Pop(); Push(a); Push(d); Push(c); Push(b); return; }
        }

        if (n == "BINARY_OP")
        {
            string operation = i.Arg >= 0 && i.Arg < t.NbOps.Length ? t.NbOps[i.Arg] : "?";
            var right = Pop(); var left = Pop();
            Push(operation == "[]" ? new Ex($"{W(left, 20)}[{Strip(right.S)}]") : Bin(operation, left, right));
            return;
        }
        if (n.StartsWith("BINARY_") || n.StartsWith("INPLACE_"))
        {
            string key = n.Substring(n.IndexOf('_') + 1);
            if (n == "BINARY_SUBSCR") { var idx = Pop(); var o = Pop(); Push(new Ex($"{W(o, 20)}[{Strip(idx.S)}]")); return; }
            if (n == "BINARY_SLICE") { var hi = Pop(); var lo = Pop(); var o = Pop(); Push(new Ex($"{W(o, 20)}[{SliceText(lo, hi)}]")); return; }
            if (OldBin.TryGetValue(key, out var sym))
            {
                var b = Pop(); var a = Pop();
                Push(Bin(n.StartsWith("INPLACE_") ? sym + "=" : sym, a, b));
                return;
            }
        }
        if (n == "STORE_SLICE") { var hi = Pop(); var lo = Pop(); var o = Pop(); Store($"{W(o, 20)}[{SliceText(lo, hi)}]"); return; }
        if (n == "BUILD_SLICE") { int c = i.Arg; var parts = new List<Ex>(); for (int q = 0; q < c; q++) parts.Insert(0, Pop()); Push(new Ex(string.Join(":", parts.Select(p => p.Const is PyNone ? "" : p.S)))); return; }
        if (n is "UNARY_NEGATIVE" or "UNARY_POSITIVE" or "UNARY_INVERT")
        {
            var a = Pop(); string op = n == "UNARY_NEGATIVE" ? "-" : n == "UNARY_POSITIVE" ? "+" : "~";
            Push(new Ex(op + W(a, 12), 12)); return;
        }
        if (n == "UNARY_NOT") { Push(Not(Pop())); return; }
        if (n == "COMPARE_OP")
        {
            var b = Pop(); var a = Pop();
            string op = Operand(i); op = Regex.Replace(op, @"^bool\((.*)\)$", "$1");
            Push(new Ex($"{W(a, 6)} {op} {W(b, 6)}", 5)
            {
                CompareOperands = new List<Ex> { a, b },
                CompareOperators = new List<string> { op },
            });
            return;
        }
        if (n == "IS_OP" || n == "CONTAINS_OP")
        {
            var b = Pop(); var a = Pop();
            string op = n == "IS_OP" ? (i.Arg != 0 ? "is not" : "is") : (i.Arg != 0 ? "not in" : "in");
            Push(new Ex($"{W(a, 6)} {op} {W(b, 6)}", 5)
            {
                CompareOperands = new List<Ex> { a, b },
                CompareOperators = new List<string> { op },
            });
            return;
        }

        if (n is "BUILD_TUPLE" or "BUILD_LIST" or "BUILD_SET")
        {
            var items = PopN(i.Arg).Select(x => x.S).ToList();
            string s = n == "BUILD_TUPLE" ? (items.Count == 1 ? "(" + items[0] + ",)" : "(" + string.Join(", ", items) + ")")
                     : n == "BUILD_LIST" ? "[" + string.Join(", ", items) + "]" : (items.Count == 0 ? "set()" : "{" + string.Join(", ", items) + "}");
            var value = new Ex(s)
            {
                Items = items,
                Kind = n == "BUILD_LIST" ? "list" : n == "BUILD_SET" ? "set" : "tuple",
            };
            if (compBuilder && i.Arg == 0 && (n is "BUILD_LIST" or "BUILD_SET"))
            {
                value.S = NewCompTemporary();
                Emit($"{value.S} = {(n == "BUILD_LIST" ? "[]" : "set()")}");
                value.Kind = n == "BUILD_LIST" ? "inline_list" : "inline_set";
                inlineCompBuilders.Add(value);
                compBuilder = false;
            }
            Push(value);
            return;
        }
        if (n == "BUILD_MAP")
        {
            var flat = PopN(i.Arg * 2); var pairs = new List<KeyValuePair<string, string>>();
            for (int q = 0; q + 1 < flat.Count; q += 2) pairs.Add(new(flat[q].S, flat[q + 1].S));
            var value = new Ex("{" + string.Join(", ", pairs.Select(p => p.Key + ": " + p.Value)) + "}")
            {
                Pairs = pairs,
                Kind = annotationMode && co.Name == "__annotate__" && i.Arg == 0 ? "class_annotations" : "dict",
            };
            if (compBuilder && i.Arg == 0)
            {
                value.S = NewCompTemporary();
                Emit($"{value.S} = {{}}");
                value.Kind = "inline_dict";
                inlineCompBuilders.Add(value);
                compBuilder = false;
            }
            Push(value); return;
        }
        if (n == "BUILD_CONST_KEY_MAP")
        {
            var keys = Pop(); var vals = PopN(i.Arg); var pairs = new List<KeyValuePair<string, string>>();
            var kl = keys.Const is PyTuple kt2 ? kt2.Items.Select(x => x.Repr()).ToList() : new List<string>();
            for (int q = 0; q < vals.Count; q++) pairs.Add(new(q < kl.Count ? kl[q] : "?", vals[q].S));
            Push(new Ex("{" + string.Join(", ", pairs.Select(p => p.Key + ": " + p.Value)) + "}") { Pairs = pairs }); return;
        }
        if (n is "LIST_EXTEND" or "SET_UPDATE")
        {
            var it = Pop(); var c = Peek(i.Arg - 1);
            if (c.Items != null)
            {
                if (it.Items != null) c.Items.AddRange(it.Items); else c.Items.Add("*" + it.S);
                string open = c.Kind == "set" ? "{" : "[";
                string close = c.Kind == "set" ? "}" : "]";
                c.S = open + string.Join(", ", c.Items) + close;
            }
            return;
        }
        if (n == "LIST_TO_TUPLE" || (n == "CALL_INTRINSIC_1" && Operand(i) == "INTRINSIC_LIST_TO_TUPLE"))
        {
            var l = Pop(); var items = l.Items ?? new List<string>();
            Push(new Ex(items.Count == 1 ? "(" + items[0] + ",)" : "(" + string.Join(", ", items) + ")") { Items = items }); return;
        }
        if (n is "LIST_APPEND" or "SET_ADD")
        {
            var v = Pop();
            if (compMode) CompElt = v.S;
            else
            {
                if (v.Kind is "inline_list" or "inline_set" or "inline_dict")
                    inlineCompBuilders.Remove(v);
                var builder = inlineCompBuilders.Count > 0 ? inlineCompBuilders[^1] : Peek(i.Arg - 1);
                if (builder.Items != null &&
                    (n == "LIST_APPEND" && builder.Kind == "list" ||
                     n == "SET_ADD" && builder.Kind == "set"))
                {
                    builder.Items.Add(v.S);
                    builder.S = builder.Kind == "set"
                        ? "{" + string.Join(", ", builder.Items) + "}"
                        : "[" + string.Join(", ", builder.Items) + "]";
                }
                else
                {
                    string method = n == "SET_ADD" ? "add" : "append";
                    Emit($"{builder.S}.{method}({v.S})");
                }
            }
            return;
        }
        if (n == "MAP_ADD")
        {
            var v = Pop(); var kx = Pop();
            if (compMode) CompElt = kx.S + ": " + v.S;
            else
            {
                if (v.Kind is "inline_list" or "inline_set" or "inline_dict")
                    inlineCompBuilders.Remove(v);
                var builder = inlineCompBuilders.Count > 0 ? inlineCompBuilders[^1] : Peek(i.Arg - 1);
                Emit($"{builder.S}[{kx.S}] = {v.S}");
            }
            return;
        }
        if (n == "DICT_UPDATE" || n == "DICT_MERGE") { var u = Pop(); var d = Peek(i.Arg - 1); if (d.Pairs != null) { d.Pairs.Add(new("**" + u.S, "")); d.S = "{" + string.Join(", ", d.Pairs.Select(p => p.Value == "" ? p.Key : p.Key + ": " + p.Value)) + "}"; } return; }
        if (n == "BUILD_STRING")
        {
            var parts = PopN(i.Arg); var sb = new StringBuilder();
            foreach (var p in parts)
            {
                if (p.Kind == "fpiece") sb.Append(p.S);
                else if (p.Const is PyStr cs) sb.Append(cs.Value.Replace("{", "{{").Replace("}", "}}"));
                else sb.Append("{" + p.S + "}");
            }
            string body = PyObj.StrRepr(sb.ToString());
            Push(new Ex("f" + body)); return;
        }
        if (n == "FORMAT_VALUE")
        {
            Ex spec = (i.Arg & 4) != 0 ? Pop() : null; var v = Pop();
            string conv = (i.Arg & 3) switch { 1 => "!s", 2 => "!r", 3 => "!a", _ => "" };
            Push(new Ex("{" + Strip(v.S) + conv + (spec?.Const is PyStr sp ? ":" + sp.Value : "") + "}") { Kind = "fpiece" }); return;
        }
        if (n == "CONVERT_VALUE") { var v = Pop(); v = new Ex(v.S, v.P) { Const = v.Const, Conv = (i.Arg & 3) switch { 1 => "!s", 2 => "!r", 3 => "!a", _ => "" } }; Push(v); return; }
        if (n == "FORMAT_SIMPLE") { var v = Pop(); Push(new Ex("{" + Strip(v.S) + v.Conv + "}") { Kind = "fpiece" }); return; }
        if (n == "FORMAT_WITH_SPEC") { var spec = Pop(); var v = Pop(); Push(new Ex("{" + Strip(v.S) + v.Conv + ":" + (spec.Const is PyStr s2 ? s2.Value : spec.S) + "}") { Kind = "fpiece" }); return; }
        if (n == "BUILD_INTERPOLATION")
        {
            Ex spec = (i.Arg & 1) != 0 ? Pop() : null;
            Ex expression = (i.Arg & 2) != 0 ? Pop() : null;
            var value = Pop();
            string sourceExpression = expression?.Const is PyStr text ? text.Value : Strip(value.S);
            string conversion = ((i.Arg >> 2) & 3) switch
            {
                1 => "!s",
                2 => "!r",
                3 => "!a",
                _ => "",
            };
            string format = spec?.Const is PyStr formatText ? ":" + formatText.Value : "";
            Push(new Ex("{" + sourceExpression + conversion + format + "}") { Kind = "interpolation" });
            return;
        }
        if (n == "BUILD_TEMPLATE")
        {
            var interpolations = Pop();
            var strings = Pop();
            if (strings.Const is not PyTuple parts || interpolations.Items == null)
            {
                Push(new Ex("<?>") { Kind = "underflow" });
                return;
            }
            var body = new StringBuilder();
            for (int index = 0; index < parts.Items.Count; index++)
            {
                if (parts.Items[index] is PyStr text)
                    body.Append(text.Value.Replace("{", "{{").Replace("}", "}}"));
                if (index < interpolations.Items.Count)
                    body.Append(interpolations.Items[index]);
            }
            Push(new Ex("t" + PyObj.StrRepr(body.ToString())));
            return;
        }
        if (n == "UNPACK_SEQUENCE" || n == "UNPACK_EX")
        {
            var v = Pop();
            int before = n == "UNPACK_EX" ? i.Arg & 0xFF : i.Arg;
            int after = n == "UNPACK_EX" ? i.Arg >> 8 : 0;
            var st = new UnpackState
            {
                N = n == "UNPACK_EX" ? before + after + 1 : i.Arg,
                StarIndex = n == "UNPACK_EX" ? before : -1,
                Src = v.S,
                For = v.Kind == "for" ? v.For : null,
            };
            for (int q = 0; q < st.N; q++) Push(new Ex("<unpack>") { Kind = "unpack", Unp = st });
            return;
        }

        if (n is "CALL_FUNCTION" or "CALL_METHOD" or "CALL" or "CALL_FUNCTION_KW" or "CALL_KW")
        {
            List<string> kw = null;
            if (n == "CALL_FUNCTION_KW" || n == "CALL_KW") { var kt3 = Pop(); kw = kt3.Const is PyTuple tt ? tt.Items.Select(x => x is PyStr s ? s.Value : x.Repr()).ToList() : new List<string>(); }
            else if (n == "CALL") { kw = kwnames; kwnames = null; }
            int pops = n == "CALL_FUNCTION" || n == "CALL_FUNCTION_KW" ? 1 : 2;
            if (n == "CALL" && stack.Count > i.Arg &&
                stack[stack.Count - i.Arg - 1].Kind == "with_exit")
                pops = 1;
            DoCall(PopN(i.Arg), kw, pops);
            return;
        }
        if (n == "CALL_FUNCTION_EX")
        {
            Ex kwx = ((i.Arg & 1) != 0 || t.Minor >= 14) ? Pop() : null; var args = Pop();
            if (kwx?.Kind == "mark" && kwx.S == "NULL") kwx = null;
            if (Peek().Kind == "mark") Pop();
            var f = Pop(); if (f.Kind == "mark") f = Pop();
            if (Peek().Kind == "mark") Pop();
            var parts = new List<string>();
            parts.Add("*" + (args.Items != null && args.Const != null ? string.Join(", ", args.Items) : args.S));
            if (kwx != null)
            {
                string keywordMapping = kwx.Kind == "dict" && kwx.Pairs is { Count: 1 } pairs &&
                    pairs[0].Value == "" && pairs[0].Key.StartsWith("**", StringComparison.Ordinal)
                        ? pairs[0].Key[2..]
                        : kwx.S;
                parts.Add("**" + keywordMapping);
            }
            Push(new Ex($"{W(f, 20)}({string.Join(", ", parts)})")); return;
        }
        if (n == "MAKE_FUNCTION") { MakeFunction(i); return; }
        if (n == "SET_FUNCTION_ATTRIBUTE")
        {
            var f = Pop(); var attr = Pop();
            if (f.Func != null)
            {
                if ((i.Arg & 1) != 0) f.Func.Defaults = attr;
                if ((i.Arg & 2) != 0) f.Func.KwDefaults = attr;
                if ((i.Arg & 4) != 0) f.Func.Annotations = attr;
                if ((i.Arg & 16) != 0) f.Func.Annotate = attr;
            }
            Push(f); return;
        }

        if (n == "IMPORT_NAME")
        {
            var from = Pop(); var level = Pop();
            int lv = level.Const is PyInt li ? (int)li.Value : 0;
            var names = from.Const is PyTuple ft ? ft.Items.Select(x => x is PyStr s ? s.Value : x.Repr()).ToList() : null;
            Push(new Ex("<module>") { Kind = "import", Imp = new ImportInfo { Module = new string('.', lv) + NameOf(i), Names = names } });
            return;
        }
        if (n == "IMPORT_FROM") { var m = Peek(); Push(new Ex(NameOf(i)) { Kind = "importfrom", FromName = NameOf(i), Imp = m.Imp }); return; }
        if (n == "IMPORT_STAR") { var m = Pop(); Emit($"from {m.Imp?.Module ?? "?"} import *"); return; }

        if (n is "RETURN_VALUE" or "RETURN_CONST")
        {
            if (suppressWithReturn)
            {
                suppressWithReturn = false;
                return;
            }
            if (IsFoldedBreakReturn(k, off))
            {
                Pop();
                Emit("break");
                RestoreLoopIteratorMarkers();
                return;
            }
            Ex v = n == "RETURN_CONST" ? ConstEx(i.RefIndex >= 0 && i.RefIndex < co.Consts.Count ? co.Consts[i.RefIndex] : null) : Pop();
            if (annotationMode)
            {
                if (v.Pairs != null) AnnotationResult = v;
                return;
            }
            if (compMode) { RestoreLoopIteratorMarkers(); return; }
            if (v.Const is PyNone && open.Any(block =>
                block.Kind == "while" && infiniteLoopEnds.Contains(block.End) && off < block.End))
            {
                Emit("break");
                CloseBlocks(off + 1);
                RestoreLoopIteratorMarkers();
                return;
            }
            if (v.Const is PyNone && (last || co.IsModule || co.IsClassBody))
            {
                RestoreLoopIteratorMarkers();
                return;
            }
            Emit(v.Const is PyNone ? "return" : "return " + Strip(v.S));
            CloseBlocks(off + 1);
            RestoreLoopIteratorMarkers();
            return;
        }
        if (n == "YIELD_VALUE")
        {
            var v = Pop();
            if (compMode) { CompElt = v.S; Push(new Ex("None")); return; }
            Push(new Ex("(yield " + v.S + ")")); return;
        }
        if (n == "YIELD_FROM")
        {
            Pop();
            var value = Pop();
            if (value.Kind == "awaitable" && value.WithManager != null)
                Push(new Ex("<with-enter>") { Kind = "with_enter", WithManager = value.WithManager, IsAsync = true });
            else if (value.Kind == "async_comp_awaitable")
                Push(new Ex(Strip(value.S)));
            else if (value.Kind == "awaitable")
                Push(new Ex("(await " + Strip(value.S) + ")") { Kind = "await" });
            else
                Push(new Ex("(yield from " + value.S + ")") { Kind = "yield_from" });
            return;
        }
        if (n == "RAISE_VARARGS")
        {
            if (i.Arg == 0) Emit("raise");
            else if (i.Arg == 1) Emit("raise " + Strip(Pop().S));
            else { var c = Pop(); var e = Pop(); Emit($"raise {Strip(e.S)} from {Strip(c.S)}"); }
            return;
        }
        if (n == "FOR_ITER") { ForIter(i, off); return; }
        if (n.StartsWith("JUMP_IF_") && n.EndsWith("_OR_POP"))
        {
            var left = Pop();
            pend.Add(new PBool { Target = i.Target ?? -1, Op = n.Contains("FALSE") ? "and" : "or", Left = left });
            return;
        }
        if (n.StartsWith("POP_JUMP_") && i.Target != null) { CondJump(i, n, off, wasCopy1); return; }
        if (i.Target != null && (n.StartsWith("JUMP_") || n == "JUMP")) { UncondJump(i, off, next); return; }

        Emit($"# incomplete reconstruction: opcode 0x{off:X} {n}{(i.HasArg ? " " + i.Arg : "")} {i.Operand}".TrimEnd());
    }

    List<Ex> PopN(int n) { var l = new List<Ex>(); for (int q = 0; q < n; q++) l.Insert(0, Pop()); return l; }
    static string SliceText(Ex lo, Ex hi) => (lo.Const is PyNone ? "" : lo.S) + ":" + (hi.Const is PyNone ? "" : hi.S);

    void Store(string target)
    {
        var v = Pop();
        if (co.IsClassBody && target is "__annotate_func__" or "__annotate__") return;
        switch (v.Kind)
        {
            case "for": lines[v.For.LineIdx] = lines[v.For.LineIdx].Replace("@@", target); return;
            case "unpack":
                v.Unp.Targets.Add(target);
                if (v.Unp.Targets.Count == v.Unp.N)
                {
                    var targets = v.Unp.Targets.ToList();
                    if (v.Unp.StarIndex >= 0)
                        targets[v.Unp.StarIndex] = "*" + targets[v.Unp.StarIndex];
                    string tg = string.Join(", ", targets);
                    if (v.Unp.For != null) lines[v.Unp.For.LineIdx] = lines[v.Unp.For.LineIdx].Replace("@@", tg);
                    else Emit($"{tg} = {Strip(v.Unp.Src)}");
                }
                return;
            case "comp_backup":
                EndCompLocal(v.S);
                return;
            case "type_param":
                return;
            case "class_locals":
                return;
            case "genexpr":
                Emit($"{target} = {v.S}");
                return;
            case "inline_list": case "inline_set": case "inline_dict":
                inlineCompBuilders.Remove(v);
                Emit($"{target} = {v.S}");
                return;
            case "with_enter":
                EmitWith(v, target);
                return;
            case "importfrom":
                Emit($"from {v.Imp?.Module ?? "?"} import {v.FromName}" + (target != v.FromName ? " as " + target : ""));
                return;
            case "import":
            {
                string mod = v.Imp?.Module ?? "?";
                string top = mod.TrimStart('.').Split('.')[0];
                Emit(target == top || mod.StartsWith(".") ? $"import {mod}" : $"import {mod} as {target}");
                return;
            }
        }
        if (v.Func?.Code.Name == "<lambda>")
        {
            Emit($"{target} = {Strip(v.S)}");
            return;
        }
        if (v.Kind == "generic_wrapper" && v.Func?.Code is PyCode genericCode)
        {
            EmitGenericDefinition(target, genericCode);
            return;
        }
        if (v.Func != null) { EmitFunc(v, target); return; }
        if (v.DecoratedFunc != null && v.DecoratedFunc.Code.Name == target)
        {
            v.DecoratedFunc.Decorators.AddRange(v.DecoratorApps ?? new List<string>());
            EmitFunc(new Ex(v.S) { Func = v.DecoratedFunc }, target);
            return;
        }
        if (v.DecoratedClass != null && v.DecoratedClass.Name == target)
        {
            v.DecoratedClass.Decorators.AddRange(v.DecoratorApps ?? new List<string>());
            EmitClass(new Ex(v.S) { Cls = v.DecoratedClass }, target);
            return;
        }
        if (v.Cls != null) { EmitClass(v, target); return; }
        if (co.IsModule && target == "__doc__" && v.Const is PyStr moduleDoc)
        {
            Emit(moduleDoc.Repr());
            return;
        }
        if (v.AugL != null && v.AugL == target) { Emit($"{target} {v.AugOp} {v.AugR}"); return; }
        Emit($"{target} = {Strip(v.S)}");
    }

    void DoCall(List<Ex> rawArgs, List<string> kw, int pops)
    {
        var callee = Pop();
        Ex second = null;
        if (pops == 2) { second = callee; callee = Pop(); }

        if (callee.Kind == "mark" && second != null) { var tmp = callee; callee = second; second = tmp; }
        if (second != null && second.Kind != "mark") rawArgs.Insert(0, second);

        var args = new List<string>();
        int nPos = rawArgs.Count - (kw?.Count ?? 0);
        for (int q = 0; q < rawArgs.Count; q++)
        {
            string value = rawArgs[q].Kind == "tuple" ? rawArgs[q].S : Strip(rawArgs[q].S);
            args.Add(q < nPos ? value : kw[q - nPos] + "=" + value);
        }

        if (callee.Kind == "build_class" && rawArgs.Count >= 2 && rawArgs[0].Func != null)
        {
            string name = rawArgs[1].Const is PyStr cs ? cs.Value : "?";
            Push(new Ex(name) { Cls = new ClassInfo { Name = name, Code = rawArgs[0].Func.Code, Bases = args.Skip(2).ToList() } });
            return;
        }
        if (callee.Func != null && callee.Func.Code.Name is "<listcomp>" or "<setcomp>" or "<dictcomp>" or "<genexpr>" && rawArgs.Count == 1)
        {
            var comprehension = callee.Func.Code;
            string expression = Comprehension(comprehension, Strip(rawArgs[0].S));
            bool isAsync = Disassembler.Disassemble(comprehension, t)
                .Any(instruction => instruction.Name == "GET_ANEXT");
            Push(new Ex(expression)
            {
                Kind = comprehension.Name == "<genexpr>" ? "genexpr" : isAsync ? "async_comp" : "",
            });
            return;
        }
        if (callee.Func?.Code.Name.StartsWith("<generic parameters of ", StringComparison.Ordinal) == true &&
            rawArgs.Count == 0)
        {
            Push(new Ex("<generic declaration>") { Kind = "generic_wrapper", Func = callee.Func });
            return;
        }
        var callResult = new Ex($"{W(callee, 20)}({string.Join(", ", args)})");
        if (rawArgs.Count == 1 && (rawArgs[0].Cls != null || rawArgs[0].DecoratedClass != null))
        {
            callResult.DecoratedClass = rawArgs[0].DecoratedClass ?? rawArgs[0].Cls;
            callResult.DecoratorApps = rawArgs[0].DecoratorApps?.ToList() ?? new List<string>();
            callResult.DecoratorApps.Add(callee.S);
            Push(callResult);
            return;
        }
        if (callee.Kind is "with_enter_callable" or "async_with_enter_callable")
        {
            Push(new Ex("<with-enter>")
            {
                Kind = "with_enter",
                WithManager = callee.WithManager,
                IsAsync = callee.IsAsync,
            });
            return;
        }
        if (callee.Kind == "with_exit")
        {
            Push(callee);
            return;
        }
        if (callee.Kind == "with_exit_callable")
        {
            Push(new Ex("<with-exit>") { Kind = "with_exit" });
            return;
        }
        if (rawArgs.Count == 1 && (kw == null || kw.Count == 0))
        {
            var candidate = rawArgs[0].DecoratedFunc ?? rawArgs[0].Func;
            if (candidate?.Code != null && candidate.Code.Name != "<lambda>")
            {
                var decoratorApps = rawArgs[0].DecoratorApps?.ToList() ?? new List<string>();
                decoratorApps.Add(callee.S);
                callResult.DecoratedFunc = candidate;
                callResult.DecoratorApps = decoratorApps;
            }
        }
        Push(callResult);
    }

    string Comprehension(PyCode child, string iter)
    {
        var c = new DecompCtx(child, t, true);
        var ls = c.Run(0);
        var clauses = new List<string>();
        foreach (var raw in ls)
        {
            string s = raw.Trim();
            if ((s.StartsWith("for ", StringComparison.Ordinal) || s.StartsWith("async for ", StringComparison.Ordinal)) &&
                s.EndsWith(":", StringComparison.Ordinal))
                clauses.Add(s.Substring(0, s.Length - 1).Replace(" .0", " " + iter));
            else if (s.StartsWith("if ") && s.EndsWith(":")) clauses.Add(s.Substring(0, s.Length - 1));
        }
        string body = (c.CompElt ?? "?") + " " + string.Join(" ", clauses);
        return child.Name switch { "<listcomp>" => "[" + body + "]", "<setcomp>" or "<dictcomp>" => "{" + body + "}", _ => "(" + body + ")" };
    }

    void EmitGenericDefinition(string target, PyCode wrapper)
    {
        var instructions = Disassembler.Disassemble(wrapper, t);
        var typeParameters = GenericTypeParameters(wrapper, instructions);
        bool isAlias = instructions.Any(instruction =>
            instruction.Name == "CALL_INTRINSIC_1" && Operand(instruction) == "INTRINSIC_TYPEALIAS");
        bool isClass = instructions.Any(instruction =>
            instruction.Name == "CALL_INTRINSIC_1" && Operand(instruction) == "INTRINSIC_SUBSCRIPT_GENERIC");
        var body = wrapper.Children.FirstOrDefault(child => child.Name == target);
        if (body == null)
            throw new DecompileException($"Generic declaration '{target}' has no matching code object.");

        string parameters = "[" + string.Join(", ", typeParameters) + "]";
        if (isAlias)
        {
            var bodyLines = new DecompCtx(body, t, false).Run(0);
            string value = bodyLines.Select(line => line.Trim())
                .FirstOrDefault(line => line.StartsWith("return ", StringComparison.Ordinal))?.Substring(7);
            if (value == null || value.Contains("incomplete reconstruction:", StringComparison.Ordinal))
                throw new DecompileException($"Type alias '{target}' could not be reconstructed safely.");
            Emit($"type {target}{parameters} = {value}");
            return;
        }

        if (isClass)
        {
            EmitClass(new Ex(target)
            {
                Cls = new ClassInfo { Name = target, Code = body, TypeParameters = typeParameters },
            }, target);
            return;
        }

        var context = new DecompCtx(wrapper, t, false);
        context.Run(0);
        var function = context.GenericFunctionResult ?? new FuncInfo { Code = body };
        function.TypeParameters = typeParameters;
        EmitFunc(new Ex("<generic function>") { Func = function }, target);
    }

    List<string> GenericTypeParameters(PyCode wrapper, List<Instruction> instructions)
    {
        var parameters = new List<string>();
        for (int index = 0; index < instructions.Count; index++)
        {
            var instruction = instructions[index];
            string intrinsic = instruction.Name is "CALL_INTRINSIC_1" or "CALL_INTRINSIC_2"
                ? Operand(instruction)
                : "";
            string prefix;
            bool hasBound;
            switch (intrinsic)
            {
                case "INTRINSIC_TYPEVAR": prefix = ""; hasBound = false; break;
                case "INTRINSIC_TYPEVARTUPLE": prefix = "*"; hasBound = false; break;
                case "INTRINSIC_PARAMSPEC": prefix = "**"; hasBound = false; break;
                case "INTRINSIC_TYPEVAR_WITH_BOUND": prefix = ""; hasBound = true; break;
                default: continue;
            }

            string name = null;
            for (int previous = index - 1; previous >= 0; previous--)
            {
                var candidate = instructions[previous];
                if (candidate.Name == "LOAD_CONST" && candidate.RefIndex >= 0 &&
                    candidate.RefIndex < wrapper.Consts.Count &&
                    wrapper.Consts[candidate.RefIndex] is PyStr text)
                {
                    name = text.Value;
                    break;
                }
            }
            if (string.IsNullOrEmpty(name)) continue;

            string parameter = prefix + name;
            if (hasBound)
            {
                var boundCode = wrapper.Children.FirstOrDefault(child => child.Name == name);
                var bound = boundCode == null ? null : new DecompCtx(boundCode, t, false).Run(0)
                    .Select(line => line.Trim())
                    .FirstOrDefault(line => line.StartsWith("return ", StringComparison.Ordinal))?.Substring(7);
                if (!string.IsNullOrEmpty(bound)) parameter += ": " + bound;
            }
            parameters.Add(parameter);
        }
        return parameters;
    }

    string NewCompTemporary()
    {
        string name;
        do name = $"__pyc_comp_{tempIndex++}";
        while (co.Names.Contains(name, StringComparer.Ordinal) ||
            co.VarNames.Contains(name, StringComparer.Ordinal) ||
            co.FreeVars.Contains(name, StringComparer.Ordinal));
        return name;
    }

    string LocalName(string name) =>
        compLocalAliases.TryGetValue(name, out var aliases) && aliases.Count > 0 ? aliases[^1] : name;

    void BeginCompLocal(string name)
    {
        string alias;
        int index = 0;
        do alias = $"__pyc_comp_local_{index++}";
        while (co.Names.Contains(alias, StringComparer.Ordinal) ||
            co.VarNames.Contains(alias, StringComparer.Ordinal) ||
            compLocalAliases.Values.Any(values => values.Contains(alias, StringComparer.Ordinal)));
        if (!compLocalAliases.TryGetValue(name, out var aliases))
            compLocalAliases[name] = aliases = new List<string>();
        aliases.Add(alias);
    }

    void EndCompLocal(string name)
    {
        if (!compLocalAliases.TryGetValue(name, out var aliases) || aliases.Count == 0) return;
        aliases.RemoveAt(aliases.Count - 1);
        if (aliases.Count == 0) compLocalAliases.Remove(name);
    }

    void EmitWith(Ex manager, string target)
    {
        int bodyIndex = IndexOfOffset(currentOffset);
        int bodyStart = bodyIndex >= 0 && bodyIndex + 1 < ins.Count
            ? ins[bodyIndex + 1].Offset
            : co.Code.Data.Length;
        int? endOffset = FindWithEnd(bodyStart, currentOffset);
        if (endOffset == null)
            throw new DecompileException($"The with block at 0x{currentOffset:X} has no matching exception-table range.");
        Emit((manager.IsAsync ? "async " : "") + "with " + manager.WithManager +
            (target == null ? "" : " as " + target) + ":");
        open.Add(new OpenBlock { Kind = "with", End = endOffset.Value, Indent = ind, HeaderIdx = lines.Count - 1 });
        ind++;
    }

    int? FindWithEnd(int bodyStart, int withOffset)
    {
        if (co.ExceptionTable.Length == 0)
        {
            int bodyIndex = IndexOfOffset(bodyStart);
            for (int index = bodyIndex - 1; index >= 0; index--)
                if (ins[index].Name is "SETUP_WITH" or "SETUP_ASYNC_WITH" &&
                    ins[index].Target is int target && target > bodyStart)
                {
                    int handlerIndex = IndexOfOffset(target);
                    bool hasWithHandler = handlerIndex >= 0 &&
                        ins.Skip(handlerIndex).Take(24)
                            .TakeWhile(instruction => instruction.Name is not ("JUMP_FORWARD" or "JUMP_BACKWARD"))
                            .Any(instruction => instruction.Name == "WITH_EXCEPT_START");
                    if (hasWithHandler)
                    {
                        for (int exitIndex = handlerIndex - 1; exitIndex > index; exitIndex--)
                            if (ins[exitIndex].Name == "POP_BLOCK")
                                return ins[exitIndex].Offset;
                    }
                    return target;
                }
            return null;
        }
        var exceptionEntries = LineTables.DecodeExc(co.ExceptionTable);
        var bodyOffsets = new HashSet<int> { withOffset, bodyStart };
        int markerIndex = IndexOfOffset(bodyStart);
        while (markerIndex >= 0 && markerIndex < ins.Count &&
            ins[markerIndex].Name is "NOP" or "NOT_TAKEN")
        {
            markerIndex++;
            if (markerIndex < ins.Count) bodyOffsets.Add(ins[markerIndex].Offset);
        }
        foreach (var entry in exceptionEntries
                     .Where(entry => bodyOffsets.Any(offset =>
                         entry.Start * 2 <= offset && entry.End * 2 > offset))
                     .OrderBy(entry => entry.End - entry.Start))
        {
            if (IsWithExceptionHandler(entry.Target * 2))
            {
                var matchingEntries = exceptionEntries.Where(candidate => candidate.Target == entry.Target).ToList();
                var bodyEntries = matchingEntries.Where(candidate => candidate.End != candidate.Target).ToList();
                return (bodyEntries.Count > 0 ? bodyEntries : matchingEntries)
                    .Max(candidate => candidate.End) * 2;
            }
        }
        return null;
    }

    bool IsWithExceptionHandler(int targetOffset)
    {
        int targetIndex = IndexOfOffset(targetOffset);
        if (targetIndex < 0) return false;

        bool hasPushExceptionInfo = false;
        int limit = Math.Min(ins.Count, targetIndex + 24);
        for (int index = targetIndex; index < limit; index++)
        {
            string name = ins[index].Name;
            if (name == "PUSH_EXC_INFO") hasPushExceptionInfo = true;
            if (name == "WITH_EXCEPT_START") return hasPushExceptionInfo;
            if (name.StartsWith("JUMP", StringComparison.Ordinal) ||
                name is "RETURN_VALUE" or "RETURN_CONST" or "RERAISE")
                return false;
        }
        return false;
    }

    void MakeFunction(Instruction i)
    {
        if (t.Minor <= 10) Pop();
        var codeEx = Pop();
        var fi = new FuncInfo { Code = codeEx.Const as PyCode };
        if (t.Minor <= 12)
        {
            if ((i.Arg & 8) != 0) Pop();
            if ((i.Arg & 4) != 0) fi.Annotations = Pop();
            if ((i.Arg & 2) != 0) fi.KwDefaults = Pop();
            if ((i.Arg & 1) != 0) fi.Defaults = Pop();
        }
        if (fi.Code == null) { Push(new Ex("<function>")); return; }
        var e = new Ex("<function " + fi.Code.Name + ">") { Func = fi };
        if (fi.Code.Name == "<lambda>")
        {
            string expr = LambdaBody(fi.Code);
            string parameters = ParameterList(fi);
            e.S = "lambda" + (parameters.Length == 0 ? "" : " " + parameters) + ": " + expr;
            e.P = 0;
        }
        Push(e);
    }

    string LambdaBody(PyCode code)
    {
        if (t.Minor < 15)
        {
            var result = StackSimulator.Analyze(code, t);
            var returns = result.Blocks.Where(block => block.TerminatorExpression != null).ToList();
            if (returns.Count != 1)
                throw new DecompileException($"Lambda '{code.QualName}' has inconsistent control flow.");
            var value = returns[0].TerminatorExpression;
            if (StackExprPrinter.TryPrintSource(value, out string expression)) return expression;
        }

        var legacyLines = new DecompCtx(code, t, false).Run(0).Select(line => line.Trim()).ToList();
        if (legacyLines.Count == 1 && legacyLines[0].StartsWith("return ", StringComparison.Ordinal) &&
            !legacyLines[0].Contains("<?>", StringComparison.Ordinal) &&
            !legacyLines[0].Contains("# error", StringComparison.Ordinal) &&
            !legacyLines[0].Contains("# OPCODE", StringComparison.Ordinal) &&
            !legacyLines[0].Contains("# 0x", StringComparison.Ordinal) &&
            !legacyLines[0].Contains("...", StringComparison.Ordinal))
            return legacyLines[0].Substring(7);
        throw new DecompileException($"Lambda '{code.QualName}' contains an expression that cannot be reconstructed safely.");
    }

    string ParameterList(FuncInfo fi)
    {
        var c = fi.Code; var names = c.VarNames;
        var annotations = GetAnnotations(fi);
        return ParameterList(fi, annotations);
    }

    string ParameterList(FuncInfo fi, Dictionary<string, string> annotations)
    {
        var c = fi.Code; var names = c.VarNames;
        var parts = new List<string>();
        var defs = fi.Defaults?.Items ?? new List<string>();
        int firstDef = c.ArgCount - defs.Count;
        for (int q = 0; q < c.ArgCount && q < names.Length; q++)
        {
            string parameter = names[q];
            if (annotations.TryGetValue(names[q], out string annotation)) parameter += ": " + annotation;
            if (q >= firstDef && q - firstDef < defs.Count) parameter += "=" + defs[q - firstDef];
            parts.Add(parameter);
            if (c.PosOnlyArgCount > 0 && q == c.PosOnlyArgCount - 1) parts.Add("/");
        }
        int pos = c.ArgCount;
        if ((c.Flags & 4) != 0 && pos + c.KwOnlyArgCount < names.Length) parts.Add("*" + names[pos + c.KwOnlyArgCount]);
        else if (c.KwOnlyArgCount > 0) parts.Add("*");
        for (int q = 0; q < c.KwOnlyArgCount && pos + q < names.Length; q++)
        {
            string nm = names[pos + q], dv = null;
            string parameter = nm;
            if (annotations.TryGetValue(nm, out string annotation)) parameter += ": " + annotation;
            if (fi.KwDefaults?.Pairs != null) foreach (var p in fi.KwDefaults.Pairs) if (p.Key.Trim('\'', '"') == nm) dv = p.Value;
            parts.Add(parameter + (dv != null ? "=" + dv : ""));
        }
        if ((c.Flags & 8) != 0)
        {
            int idx = pos + c.KwOnlyArgCount + ((c.Flags & 4) != 0 ? 1 : 0);
            if (idx < names.Length)
            {
                string parameter = names[idx];
                if (annotations.TryGetValue(names[idx], out string annotation)) parameter += ": " + annotation;
                parts.Add("**" + parameter);
            }
        }
        return string.Join(", ", parts);
    }

    string Signature(FuncInfo fi)
    {
        var annotations = GetAnnotations(fi);
        string signature = ParameterList(fi, annotations) + ")";
        return annotations.TryGetValue("return", out string returnAnnotation)
            ? signature + " -> " + returnAnnotation
            : signature;
    }

    Dictionary<string, string> GetAnnotations(FuncInfo fi)
    {
        var annotations = new Dictionary<string, string>(StringComparer.Ordinal);
        if (fi.Annotations != null)
        {
            if (fi.Annotations.Pairs != null)
            {
                foreach (var pair in fi.Annotations.Pairs)
                    annotations[AnnotationName(pair.Key)] = pair.Value;
            }
            else if (fi.Annotations.Items != null && fi.Annotations.Items.Count % 2 == 0)
            {
                for (int i = 0; i < fi.Annotations.Items.Count; i += 2)
                    annotations[AnnotationName(fi.Annotations.Items[i])] = fi.Annotations.Items[i + 1];
            }
            else
                throw new DecompileException($"Annotations for '{fi.Code.QualName}' have an unsupported representation.");
        }

        if (annotations.Count == 0 && fi.Annotate != null)
        {
            if (fi.Annotate.Func?.Code is not PyCode annotateCode)
                throw new DecompileException($"Lazy annotations for '{fi.Code.QualName}' are not backed by a code object.");
            if (t.Minor >= 14)
            {
                var context = new DecompCtx(annotateCode, t, false, annotationMode: true);
                context.Run(0);
                var pairs = context.AnnotationResult?.Pairs;
                if (pairs == null)
                    throw new DecompileException($"Annotations for '{fi.Code.QualName}' did not produce a dictionary.");
                foreach (var pair in pairs)
                    annotations[AnnotationName(pair.Key)] = pair.Value;
                return annotations;
            }
            var analysis = StackSimulator.Analyze(annotateCode, t);
            var returnedDictionary = analysis.Blocks.Select(block => block.TerminatorExpression)
                .FirstOrDefault(expression => expression?.Kind == StackExprKind.Dictionary);
            if (analysis.HasErrors || returnedDictionary == null || returnedDictionary.Items.Count % 2 != 0)
                throw new DecompileException($"Annotations for '{fi.Code.QualName}' could not be reconstructed safely.");
            for (int i = 0; i < returnedDictionary.Items.Count; i += 2)
            {
                var key = returnedDictionary.Items[i];
                if (key.Constant is not PyStr name ||
                    !StackExprPrinter.TryPrintSource(returnedDictionary.Items[i + 1], out string value))
                    throw new DecompileException($"Annotations for '{fi.Code.QualName}' contain an opaque expression.");
                annotations[name.Value] = value;
            }
        }
        return annotations;
    }

    static string AnnotationName(string key)
    {
        key = key?.Trim() ?? "";
        if (key.Length >= 2 && ((key[0] == '\'' && key[^1] == '\'') || (key[0] == '"' && key[^1] == '"')))
            return key.Substring(1, key.Length - 2);
        return key;
    }

    void EmitFunc(Ex f, string name)
    {
        var fi = f.Func;
        foreach (var d in Enumerable.Reverse(fi.Decorators)) Emit("@" + d);
        string pre = (fi.Code.Flags & 0x80) != 0 || (fi.Code.Flags & 0x200) != 0 ? "async " : "";
        string typeParameters = fi.TypeParameters.Count == 0 ? "" : "[" + string.Join(", ", fi.TypeParameters) + "]";
        Emit($"{pre}def {name}{typeParameters}({Signature(fi)}:");
        var body = new DecompCtx(fi.Code, t, false).Run(ind + 1);
        if (GetDocstring(fi.Code) is PyStr docstring)
            body.Insert(0, Sp(ind + 1) + docstring.Repr());
        lines.AddRange(body);
    }

    static readonly Regex ClassBoiler = new(@"^\s*(__module__|__qualname__|__firstlineno__|__static_attributes__|__type_params__|__classdictcell__|__classcell__|__doc__|__annotate_func__)\b.*$|^\s*return (__classdictcell__|__classcell__|__class__)\s*$");

    void EmitClass(Ex c, string target)
    {
        var ci = c.Cls;
        foreach (var decorator in Enumerable.Reverse(ci.Decorators)) Emit("@" + decorator);
        string typeParameters = ci.TypeParameters.Count == 0 ? "" : "[" + string.Join(", ", ci.TypeParameters) + "]";
        Emit($"class {target}{typeParameters}" + (ci.Bases.Count > 0 ? "(" + string.Join(", ", ci.Bases) + ")" : "") + ":");
        var body = new DecompCtx(ci.Code, t, false).Run(ind + 1).Where(l => !ClassBoiler.IsMatch(l)).ToList();
        var annotations = GetClassAnnotations(ci.Code);
        var declarations = new List<string>();
        foreach (var (name, annotation) in annotations)
        {
            string assignmentPrefix = Sp(ind + 1) + name + " =";
            int assignmentIndex = body.FindIndex(line => line.StartsWith(assignmentPrefix, StringComparison.Ordinal));
            if (assignmentIndex >= 0)
                body[assignmentIndex] = Sp(ind + 1) + name + ": " + annotation + " =" +
                    body[assignmentIndex].Substring(assignmentPrefix.Length);
            else
                declarations.Add(Sp(ind + 1) + name + ": " + annotation);
        }
        if (GetDocstring(ci.Code) is PyStr docstring)
            body.Insert(0, Sp(ind + 1) + docstring.Repr());
        body.InsertRange(body.Count > 0 && GetDocstring(ci.Code) is PyStr ? 1 : 0, declarations);
        if (body.Count == 0 || body.All(l => l.Trim() == "pass")) body = new List<string> { Sp(ind + 1) + "pass" };
        lines.AddRange(body);
    }

    Dictionary<string, string> GetClassAnnotations(PyCode code)
    {
        var annotateCode = code.Children.FirstOrDefault(child => child.Name == "__annotate__");
        if (annotateCode == null) return new Dictionary<string, string>(StringComparer.Ordinal);
        var context = new DecompCtx(annotateCode, t, false, annotationMode: true);
        context.Run(0);
        return context.ClassAnnotations;
    }

    static PyStr GetDocstring(PyCode code)
    {
        if (code.Minor >= 14 && (code.Flags & 0x4000000) == 0) return null;
        return code.Consts.FirstOrDefault() as PyStr;
    }

    void ForIter(Instruction i, int off)
    {
        var iter = Pop();
        int end = i.Target ?? int.MaxValue;
        int elseTo = -1;
        int bodyEndIndex = IndexOfOffset(end);
        for (int index = IndexOfOffset(off) + 1; index < bodyEndIndex; index++)
        {
            if (ins[index].Name.StartsWith("JUMP_", StringComparison.Ordinal) &&
                ins[index].Target is int target && target > end)
                elseTo = Math.Max(elseTo, target);
        }
        Emit($"for @@ in {Strip(iter.S)}:");
        int hdr = lines.Count - 1;
        var forState = new ForState { LineIdx = hdr };
        open.Add(new OpenBlock { Kind = "for", End = end, Indent = ind, HeaderIdx = hdr, Top = off, For = forState, ElseTo = elseTo });
        ind++;
        Push(new Ex("<for-iterator>") { Kind = "for_iterator", For = forState });
        Push(new Ex("<for>") { Kind = "for", For = forState });
    }

    void CondJump(Instruction i, string n, int off, bool wasCopy1)
    {
        var c = Pop();
        int T = i.Target ?? -1;
        bool ifTrue = n.Contains("IF_TRUE"), ifFalse = n.Contains("IF_FALSE");

        if (wasCopy1 && T > off && (ifTrue || ifFalse))
        {
            var left = Pop();
            pend.Add(new PBool { Target = T, Op = ifFalse ? "and" : "or", Left = left });
            skipPop = true;
            return;
        }

        if (ifFalse && T > off && IsBooleanReturnJoin(IndexOfOffset(off), T))
        {
            pend.Add(new PBool { Target = T, Op = "and", Left = c });
            return;
        }

        Ex cond = ifFalse ? c
                : ifTrue ? Not(c)
                : n.Contains("IF_NOT_NONE") ? new Ex($"{W(c, 6)} is None", 5)
                : new Ex($"{W(c, 6)} is not None", 5);
        if (T <= off)
        {
            if (compMode && (ifFalse || ifTrue) &&
                open.Any(block => block.Kind == "for" && block.Top == T))
                Emit("if " + Strip(cond.S) + ":");
            else
                Emit($"# if {Strip(cond.S)}: goto 0x{T:X}");
            return;
        }

        if (open.Count > 0 && open[^1].Kind == "if" && open[^1].End == T && lines.Count - 1 == open[^1].HeaderIdx && open[^1].CondEx != null)
        {
            var ob = open[^1];
            var merged = new Ex($"{W(ob.CondEx, 4)} and {W(cond, 4)}", 3);
            ob.CondEx = merged;
            lines[ob.HeaderIdx] = Sp(ob.Indent) + "if " + Strip(merged.S) + ":";
            return;
        }

        bool isWhile = loopConditionOffsets.Contains(off);
        Emit((isWhile ? "while " : "if ") + Strip(cond.S) + ":");
        open.Add(new OpenBlock { Kind = isWhile ? "while" : "if", End = T, Indent = ind, HeaderIdx = lines.Count - 1, CondEx = cond });
        ind++;
    }

    void UncondJump(Instruction i, int off, int next)
    {
        int T = i.Target.Value;
        if (T == next) return;
        if (IsComparisonJoinJump(off, T)) return;
        OpenBlock loop = null;
        for (int q = open.Count - 1; q >= 0; q--) if (open[q].Kind is "for" or "while") { loop = open[q]; break; }

        if (T > off)
        {
            if (loop != null && T >= loop.End) { Emit("break"); CloseBlocks(off + 1); RestoreLoopIteratorMarkers(); return; }
            if (open.Count > 0 && open[^1].Kind == "if" && open[^1].End == next && T > next) { open[^1].ElseTo = T; return; }
            Emit($"# goto 0x{T:X}");
            return;
        }

        if (loop != null)
        {
            if (next == loop.End || next >= loop.End) return;
            Emit("continue");
            CloseBlocks(off + 1);
            return;
        }

        bool IsComparisonJoinJump(int offset, int target)
        {
            int jumpIndex = IndexOfOffset(offset);
            int targetIndex = IndexOfOffset(target);
            if (jumpIndex <= 0 || targetIndex <= jumpIndex || ins[jumpIndex - 1].Name != "COMPARE_OP")
                return false;

            for (int branchIndex = jumpIndex - 1; branchIndex >= Math.Max(0, jumpIndex - 12); branchIndex--)
            {
                if (!ins[branchIndex].Name.StartsWith("POP_JUMP", StringComparison.Ordinal) ||
                    ins[branchIndex].Target is not int branchTarget ||
                    branchTarget <= offset || branchTarget >= target)
                    continue;
                int cleanupIndex = IndexOfOffset(branchTarget);
                if (cleanupIndex <= jumpIndex || cleanupIndex >= targetIndex) continue;
                bool hasPop = false;
                bool isCleanup = true;
                for (int index = cleanupIndex; index < targetIndex; index++)
                {
                    string name = ins[index].Name;
                    if (name == "POP_TOP") hasPop = true;
                    else if (name is not ("SWAP" or "NOT_TAKEN"))
                    {
                        isCleanup = false;
                        break;
                    }
                }
                if (isCleanup && hasPop) return true;
            }
            return false;
        }
        Emit($"# goto 0x{T:X}");
    }
}