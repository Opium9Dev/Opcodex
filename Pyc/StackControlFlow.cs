namespace Opcodex.Pyc;

internal static class StackControlFlowAnalyzer
{
    public static void Analyze(StackSimulationResult result)
    {
        var reachable = result.Blocks.Where(b => b.Reachable).Select(b => b.Id).ToHashSet();
        if (reachable.Count == 0) return;

        ComputeDominators(result.Blocks, reachable);
        ComputePostDominators(result.Blocks, reachable);
        BuildBranches(result);
        BuildLoops(result, reachable);
    }

    static void ComputeDominators(List<StackBlock> blocks, HashSet<int> reachable)
    {
        foreach (var block in blocks)
        {
            block.Dominators.Clear();
            if (!reachable.Contains(block.Id)) continue;
            if (block.Id == 0) block.Dominators.Add(block.Id);
            else block.Dominators.UnionWith(reachable);
        }

        bool changed;
        do
        {
            changed = false;
            foreach (var block in blocks.Where(b => reachable.Contains(b.Id) && b.Id != 0))
            {
                var predecessors = block.Predecessors.Select(e => e.FromBlock)
                    .Where(reachable.Contains).Distinct().ToList();
                var updated = predecessors.Count == 0
                    ? new HashSet<int>()
                    : new HashSet<int>(blocks[predecessors[0]].Dominators);
                foreach (int predecessor in predecessors.Skip(1))
                    updated.IntersectWith(blocks[predecessor].Dominators);
                updated.Add(block.Id);
                if (!block.Dominators.SetEquals(updated))
                {
                    block.Dominators.Clear();
                    block.Dominators.UnionWith(updated);
                    changed = true;
                }
            }
        } while (changed);

        foreach (var block in blocks.Where(b => reachable.Contains(b.Id)))
        {
            var strict = block.Dominators.Where(id => id != block.Id).ToList();
            block.ImmediateDominator = strict
                .OrderByDescending(id => blocks[id].Dominators.Count)
                .Select(id => (int?)id).FirstOrDefault();
        }
    }

    static void ComputePostDominators(List<StackBlock> blocks, HashSet<int> reachable)
    {
        var exits = reachable.Where(id => !blocks[id].Successors.Any(e => reachable.Contains(e.ToBlock))).ToHashSet();
        var canReachExit = new HashSet<int>(exits);
        var work = new Queue<int>(exits);
        while (work.Count > 0)
        {
            int current = work.Dequeue();
            foreach (var edge in blocks[current].Predecessors)
                if (reachable.Contains(edge.FromBlock) && canReachExit.Add(edge.FromBlock))
                    work.Enqueue(edge.FromBlock);
        }

        foreach (var block in blocks)
        {
            block.PostDominators.Clear();
            if (!reachable.Contains(block.Id)) continue;
            if (exits.Contains(block.Id)) block.PostDominators.Add(block.Id);
            else if (canReachExit.Contains(block.Id)) block.PostDominators.UnionWith(canReachExit);
            else block.PostDominators.Add(block.Id);
        }

        bool changed;
        do
        {
            changed = false;
            foreach (int id in canReachExit.Where(id => !exits.Contains(id)))
            {
                var block = blocks[id];
                var successors = block.Successors.Select(e => e.ToBlock)
                    .Where(reachable.Contains).Distinct().ToList();
                if (successors.Any(s => !canReachExit.Contains(s)))
                {
                    if (block.PostDominators.Count != 1 || !block.PostDominators.Contains(id))
                    {
                        block.PostDominators.Clear();
                        block.PostDominators.Add(id);
                        changed = true;
                    }
                    continue;
                }
                var updated = successors.Count == 0
                    ? new HashSet<int>()
                    : new HashSet<int>(blocks[successors[0]].PostDominators);
                foreach (int successor in successors.Skip(1))
                    updated.IntersectWith(blocks[successor].PostDominators);
                updated.Add(id);
                if (!block.PostDominators.SetEquals(updated))
                {
                    block.PostDominators.Clear();
                    block.PostDominators.UnionWith(updated);
                    changed = true;
                }
            }
        } while (changed);

        foreach (var block in blocks.Where(b => reachable.Contains(b.Id)))
        {
            var strict = block.PostDominators.Where(id => id != block.Id).ToList();
            block.ImmediatePostDominator = strict
                .OrderByDescending(id => blocks[id].PostDominators.Count)
                .Select(id => (int?)id).FirstOrDefault();
        }
    }

    static void BuildBranches(StackSimulationResult result)
    {
        foreach (var block in result.Blocks)
        {
            block.JoinBlockId = null;
            if (block.BranchCondition == null || block.BranchTargetWhenTrue is not bool targetIsTrue ||
                block.BranchTargetBlock is not int target)
                continue;

            var fallThrough = block.Successors.FirstOrDefault(e => e.Kind == StackEdgeKind.BranchFallThrough);
            int? fallThroughTarget = fallThrough?.ToBlock;
            int? trueTarget = targetIsTrue ? target : fallThroughTarget;
            int? falseTarget = targetIsTrue ? fallThroughTarget : target;
            block.JoinBlockId = block.ImmediatePostDominator;
            result.Branches.Add(new StackBranch(block.Id, block.BranchCondition, trueTarget, falseTarget, block.JoinBlockId));
        }
    }

    static void BuildLoops(StackSimulationResult result, HashSet<int> reachable)
    {
        var byHeader = new Dictionary<int, (HashSet<int> Latches, HashSet<int> Body)>();
        foreach (var edge in result.Edges.Where(e => e.Kind != StackEdgeKind.Exception))
        {
            if (!reachable.Contains(edge.FromBlock) || !reachable.Contains(edge.ToBlock) ||
                !result.Blocks[edge.FromBlock].Dominators.Contains(edge.ToBlock))
                continue;

            int header = edge.ToBlock;
            if (!byHeader.TryGetValue(header, out var loop))
                loop = (new HashSet<int>(), new HashSet<int> { header });
            loop.Latches.Add(edge.FromBlock);
            var work = new Stack<int>();
            work.Push(edge.FromBlock);
            while (work.Count > 0)
            {
                int current = work.Pop();
                if (!loop.Body.Add(current) || current == header) continue;
                foreach (var predecessor in result.Blocks[current].Predecessors)
                    if (reachable.Contains(predecessor.FromBlock) &&
                        result.Blocks[predecessor.FromBlock].Dominators.Contains(header))
                        work.Push(predecessor.FromBlock);
            }
            byHeader[header] = loop;
        }

        result.Loops.Clear();
        foreach (var (header, loop) in byHeader.OrderBy(pair => pair.Key))
        {
            var body = loop.Body.OrderBy(id => id).ToList();
            result.Loops.Add(new StackLoop(header, loop.Latches.OrderBy(id => id).ToList(), body));
        }

        foreach (var block in result.Blocks) block.LoopHeaderId = null;
        foreach (var loop in result.Loops.OrderByDescending(loop => loop.Body.Count))
            foreach (int id in loop.Body)
                result.Blocks[id].LoopHeaderId = loop.HeaderBlockId;
    }
}
