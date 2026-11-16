using System.Text;
using System.Text.RegularExpressions;
using System.Windows;
using System.Windows.Controls;
using System.Windows.Documents;
using System.Windows.Input;
using System.Windows.Media;
using Microsoft.Win32;
using Opcodex.Pyc;

namespace Opcodex;

public partial class MainWindow
{
    public static readonly RoutedCommand NopCommand = new("Nop", typeof(MainWindow));
    public static readonly RoutedCommand GotoCommand = new("Goto", typeof(MainWindow));

    void NopCmd_Executed(object s, ExecutedRoutedEventArgs e) => Nop_Click(s, e);
    void FindCmd_Executed(object s, ExecutedRoutedEventArgs e) => Find_Click(s, e);
    void GotoCmd_Executed(object s, ExecutedRoutedEventArgs e) => Goto_Click(s, e);

    int CodeIdx(PyCode c) => _pyc == null || c == null ? -1 : _pyc.AllCode.IndexOf(c);
    PyCode CodeAt(int i) => _pyc != null && i >= 0 && i < _pyc.AllCode.Count ? _pyc.AllCode[i] : null;

    void RefreshPatchList()
    {
        _patches.Clear();
        foreach (var r in _patchRecs) _patches.Add(new Row(r.OffsetText, r.OrigText, r.NewText, r.Time));
    }

    void Fail(string what, string msg)
    {
        Log($"{what}: {msg}");
        StatusLeft.Text = $"{what}: {msg}";
        Dlg.Show(this, msg, "Opcodex - " + what, MessageBoxButton.OK, MessageBoxImage.Warning);
    }

    List<(int FileOffset, byte[] Bytes)> PendingPatches() =>
        _patchRecs.Where(r => r.NewBytes != null).Select(r => (r.FileOffset, r.NewBytes)).ToList();

    void SelectCode(PyCode c)
    {
        if (c == null || !_nodes.TryGetValue(c, out var node)) return;
        for (var p = node.Parent as TreeViewItem; p != null; p = p.Parent as TreeViewItem) p.IsExpanded = true;
        node.IsSelected = true;
        node.BringIntoView();
    }

    void Navigate(int off)
    {
        CenterTabs.SelectedIndex = 0;
        int idx = -1;
        for (int i = 0; i < _lines.Count; i++)
        {
            var ins = _lines[i].Insn;
            if (ins != null && ins.Offset <= off) idx = i; else if (ins != null) break;
        }
        if (idx < 0) { StatusLeft.Text = $"No instruction at 0x{off:X}"; return; }
        Disasm.SelectedIndex = idx;
        Disasm.ScrollIntoView(_lines[idx]);
        Disasm.Focus();
    }

    void ApplyText(int i, string text, StructOp op)
    {
        var o = _lines[i];
        var insns = _lines.Select(l => l.Insn).ToList();
        try
        {
            if (op == StructOp.Replace)
            {
                var plan = PatchService.Plan(_pyc, _cur, insns, i, text);
                if (!plan.IsStructural)
                {
                    if (_cur.Code.SharedRefs > 0) Log("Warning: this co_code payload is shared with another code object.");
                    DoPatch(i, PatchedLine(i, plan.InPlace), plan.InPlace);
                }
                else
                    DoStructural(StructOp.Replace, o.Insn.Offset, plan.Asm,
                                 $"Replace {o.Offset} with '{text.Trim()}' ({plan.Reason})");
            }
            else
            {
                var a = Assembler.Parse(_pyc.Opcodes, _cur, text);
                DoStructural(op, o.Insn.Offset, a, $"Insert '{text.Trim()}' before {o.Offset}");
            }
        }
        catch (AsmException ex) { Fail("Assemble", ex.Message); }
    }

    DisasmLine PatchedLine(int idx, byte[] bytes)
    {
        var old = _lines[idx];
        string name = _pyc.Opcodes.Name(bytes[0]), arg = "", operand = "";
        try
        {
            int ci = CodeIdx(_cur);
            var patches = _patchRecs.Where(r => r.NewBytes != null && !(r.Code == _cur && r.Offset == old.Insn.Offset))
                                    .Select(r => (r.FileOffset, r.NewBytes)).ToList();
            patches.Add((old.Insn.FileOffset, bytes));
            var pf = PycFile.Parse(PatchService.Bake(_pyc, patches), _pyc.Path);
            var ins = Disassembler.Disassemble(pf.AllCode[ci], pf.Opcodes).FirstOrDefault(x => x.Offset == old.Insn.Offset);
            if (ins != null) { name = ins.Name; arg = ins.HasArg ? ins.Arg.ToString() : ""; operand = ins.Operand; }
        }
        catch (Exception) { if (_pyc.Opcodes.HasArg(bytes[0])) arg = bytes[1].ToString(); }
        string hex = DisasmExport.Hex(new[] { bytes[0], bytes[1] }) + (bytes.Length > 2 ? $" x{bytes.Length / 2}" : "");
        return new DisasmLine("patched", old.Offset, hex, name, arg, operand, "; patched", OpColor(name), Patched, old.Insn);
    }

    void DoStructural(StructOp op, int offset, AsmInsn asm, string label)
    {
        int ci = CodeIdx(_cur);
        PycFile result; string note;
        try
        {
            var baked = PatchService.Bake(_pyc, PendingPatches());
            var fresh = PycFile.Parse(baked, _pyc.Path);
            result = PatchService.ApplyStructural(fresh, ci, offset, op, asm, out note);
        }
        catch (Exception ex) when (ex is AsmException || ex is PycFormatException)
        {
            Fail("Patch", ex.Message);
            return;
        }
        CommitSnapshot(result, label, ci, offset);
        Log($"{label}: {note}");
        if (_patchRecs.Count == 0) StatusLeft.Text = "Structural edit applied: " + note;
    }

    void CommitSnapshot(PycFile result, string label, int ci, int off)
    {
        var h = new HistoryEntry
        {
            IsSnapshot = true, Label = label, CodeIndex = ci, Offset = off,
            RawBefore = _pyc.Raw, RawAfter = result.Raw,
            RecsBefore = _patchRecs.Select(r => r.Clone()).ToList(),
        };
        _undo.Add(h);
        _redo.Clear();
        ReplaceFile(result, ci, off, null);
    }

    void ApplySnapshot(byte[] raw, List<PatchRec> recs, int ci, int off)
    {
        var pf = PycFile.Parse(raw, _pyc.Path);
        ReplaceFile(pf, ci, off, recs?.Select(r => r.Clone()).ToList());
    }

    void ReplaceFile(PycFile pyc, int ci, int off, List<PatchRec> recs)
    {
        _pyc = pyc;
        _cur = null;
        _patchRecs.Clear();
        if (recs != null)
            foreach (var r in recs)
            {
                r.Code = CodeAt(r.CodeIndex);
                if (r.Code != null) _patchRecs.Add(r);
            }
        RefreshPatchList();
        _base.Clear(); _lines.Clear(); _nodes.Clear();

        FillHeader();
        FillImports();
        BuildTree();
        var target = CodeAt(ci);
        if (target != null && target != _cur) SelectCode(target);
        Navigate(off);
        UpdateStatus();
    }

    void Invert_Click(object s, RoutedEventArgs e)
    {
        int i = Disasm.SelectedIndex;
        if (_pyc == null || _cur == null || i < 0 || _lines[i].Insn == null) { StatusLeft.Text = "Select a conditional jump first"; return; }
        var o = _lines[i];
        var bytes = PatchService.InvertJump(_pyc, _cur, o.Insn, out string newName, out string err);
        if (bytes == null) { Fail("Invert jump", err); return; }
        DoPatch(i, PatchedLine(i, bytes), bytes);
    }

    void Assemble_Click(object s, RoutedEventArgs e)
    {
        int i = Disasm.SelectedIndex;
        if (_pyc == null || _cur == null || i < 0 || _lines[i].Insn == null) { StatusLeft.Text = "Select an instruction first"; return; }

        var w = new ChromeWindow("Assemble instruction")
        {
            Width = 440, SizeToContent = SizeToContent.Height, Owner = this, WindowStartupLocation = WindowStartupLocation.CenterOwner,
        };
        var tb = new TextBox { Text = PatchBox.Text, FontFamily = new FontFamily("Consolas"), Margin = new Thickness(0, 4, 0, 8) };
        var rRep = new RadioButton { Content = "Replace the selected instruction", IsChecked = true, Margin = new Thickness(0, 2, 0, 2) };
        var rIns = new RadioButton { Content = "Insert before the selected instruction", Margin = new Thickness(0, 2, 0, 2) };
        var rDel = new RadioButton { Content = "Delete the selected instruction", Margin = new Thickness(0, 2, 0, 8) };
        rDel.Checked += (_, _) => tb.IsEnabled = false;
        rRep.Checked += (_, _) => tb.IsEnabled = true;
        rIns.Checked += (_, _) => tb.IsEnabled = true;
        var ok = new Button { Content = "OK", IsDefault = true, Width = 70, Margin = new Thickness(0, 0, 6, 0) };
        var cancel = new Button { Content = "Cancel", IsCancel = true, Width = 70 };
        ok.Click += (_, _) => w.DialogResult = true;
        var hint = new TextBlock
        {
            Foreground = (Brush)FindResource("Muted"), TextWrapping = TextWrapping.Wrap, Margin = new Thickness(0, 0, 0, 8),
            Text = "Examples:  LOAD_CONST 'text'   LOAD_CONST 3   LOAD_GLOBAL print + NULL   POP_JUMP_IF_FALSE 0x2C   POP_TOP\n" +
                   "Same-size edits are written in place; anything else (new constant/name, different size, insert, delete) re-encodes the code object and fixes jumps, line table and exception table.",
        };
        var buttons = new StackPanel { Orientation = Orientation.Horizontal, HorizontalAlignment = HorizontalAlignment.Right };
        buttons.Children.Add(ok); buttons.Children.Add(cancel);
        var panel = new StackPanel { Margin = new Thickness(14) };
        panel.Children.Add(new TextBlock { Text = $"At {_lines[i].Offset}:  {_lines[i].Opcode} {_lines[i].Arg} {_lines[i].Operand}".TrimEnd(), FontFamily = new FontFamily("Consolas") });
        panel.Children.Add(tb); panel.Children.Add(rRep); panel.Children.Add(rIns); panel.Children.Add(rDel);
        panel.Children.Add(hint); panel.Children.Add(buttons);
        w.Body = panel;
        w.Loaded += (_, _) => { tb.Focus(); tb.SelectAll(); };
        if (w.ShowDialog() != true) return;

        if (rDel.IsChecked == true)
        {
            DoStructural(StructOp.Delete, _lines[i].Insn.Offset, null, $"Delete instruction {_lines[i].Offset}");
            return;
        }
        PatchBox.Text = tb.Text;
        ApplyText(i, tb.Text, rIns.IsChecked == true ? StructOp.InsertBefore : StructOp.Replace);
    }

    void Rebuild_Click(object s, RoutedEventArgs e)
    {
        if (_pyc == null) { Log("Rebuild: no file loaded."); return; }
        bool clear = false;
        if (_pyc.HashBased && _pyc.CheckSource)
        {
            var r = Dlg.Show(this,
                "This .pyc is hash-based with check_source set: Python re-validates it against the .py source and may discard modified bytecode.\n\nClear the check_source flag?",
                "Opcodex - Rebuild", MessageBoxButton.YesNoCancel, MessageBoxImage.Question);
            if (r == MessageBoxResult.Cancel) return;
            clear = r == MessageBoxResult.Yes;
        }
        try
        {
            var fresh = PycFile.Parse(PatchService.Bake(_pyc, PendingPatches()), _pyc.Path);
            var result = PatchService.Rebuild(fresh, clear);
            int ci = Math.Max(0, CodeIdx(_cur));
            int off = Disasm.SelectedItem is DisasmLine l && l.Insn != null ? l.Insn.Offset : 0;
            CommitSnapshot(result, "Rebuild header / marshal", ci, off);
            Log($"Rebuilt: {_pyc.Raw.Length} bytes, marshal rewritten without shared references" + (clear ? ", check_source cleared." : "."));
        }
        catch (Exception ex) when (ex is AsmException || ex is PycFormatException)
        {
            Fail("Rebuild", ex.Message);
        }
    }

    const string SearchHint = "Search opcode, const, name...";

    void Search_GotFocus(object s, RoutedEventArgs e)
    {
        if (SearchBox.Text != SearchHint) return;
        SearchBox.Text = "";
        SearchBox.Foreground = (Brush)FindResource("Fg");
    }

    void Search_LostFocus(object s, RoutedEventArgs e)
    {
        if (SearchBox.Text.Length > 0) return;
        SearchBox.Text = SearchHint;
        SearchBox.Foreground = (Brush)FindResource("Muted");
    }

    void Search_KeyDown(object s, KeyEventArgs e)
    {
        if (e.Key == Key.Enter) { FindNext(SearchBox.Text, (Keyboard.Modifiers & ModifierKeys.Shift) != 0); e.Handled = true; }
        else if (e.Key == Key.Escape) { Disasm.Focus(); e.Handled = true; }
    }

    void Find_Click(object s, RoutedEventArgs e) => ShowFindBar();

    void GlobalSearch_Click(object s, RoutedEventArgs e)
    {
        SearchBox.Focus();
        SearchBox.SelectAll();
    }

    static bool LineMatches(DisasmLine l, string q)
    {
        var c = StringComparison.OrdinalIgnoreCase;
        return l.Opcode.Contains(q, c) || (l.Operand ?? "").Contains(q, c) || (l.Comment ?? "").Contains(q, c) ||
               (l.Offset ?? "").Contains(q, c);
    }

    void FindNext(string q, bool back)
    {
        if (_pyc == null || string.IsNullOrWhiteSpace(q) || q == SearchHint) return;
        q = q.Trim();
        int n = _lines.Count, start = Disasm.SelectedIndex;
        for (int step = 1; step <= n; step++)
        {
            int k = back ? ((start - step) % n + n) % n : (start + step) % n;
            if (!LineMatches(_lines[k], q)) continue;
            CenterTabs.SelectedIndex = 0;
            Disasm.SelectedIndex = k;
            Disasm.ScrollIntoView(_lines[k]);
            StatusLeft.Text = $"Found '{q}' at {_lines[k].Offset}";
            return;
        }

        var codes = _pyc.AllCode;
        int c0 = Math.Max(0, CodeIdx(_cur));
        for (int d = 1; d < codes.Count; d++)
        {
            int ci = (c0 + d) % codes.Count;
            var hit = Disassembler.Disassemble(codes[ci], _pyc.Opcodes).FirstOrDefault(x => InsnSearch.Matches(x, q));
            if (hit == null) continue;
            SelectCode(codes[ci]);
            Navigate(hit.Offset);
            StatusLeft.Text = $"Found '{q}' in {codes[ci].QualName} at 0x{hit.Offset:X4}";
            return;
        }
        StatusLeft.Text = $"Not found: {q}";
    }

    void Goto_Click(object s, RoutedEventArgs e)
    {
        if (_pyc == null || _cur == null) return;
        string txt = InputBox("Go to offset", "Offset in co_code (hex such as 0x2C, or @44 for decimal):", "0x");
        if (txt == null) return;
        if (!InsnSearch.TryParseOffset(txt, out int off)) { StatusLeft.Text = $"Invalid offset: {txt}"; return; }
        Navigate(off);
    }

    string InputBox(string title, string label, string initial)
    {
        var w = new ChromeWindow(title)
        {
            Width = 380, SizeToContent = SizeToContent.Height, Owner = this, WindowStartupLocation = WindowStartupLocation.CenterOwner,
        };
        var tb = new TextBox { Text = initial, FontFamily = new FontFamily("Consolas"), Margin = new Thickness(0, 6, 0, 10) };
        var ok = new Button { Content = "OK", IsDefault = true, Width = 70, Margin = new Thickness(0, 0, 6, 0) };
        var cancel = new Button { Content = "Cancel", IsCancel = true, Width = 70 };
        string result = null;
        ok.Click += (_, _) => { result = tb.Text; w.DialogResult = true; };
        var buttons = new StackPanel { Orientation = Orientation.Horizontal, HorizontalAlignment = HorizontalAlignment.Right };
        buttons.Children.Add(ok); buttons.Children.Add(cancel);
        var panel = new StackPanel { Margin = new Thickness(14) };
        panel.Children.Add(new TextBlock { Text = label, TextWrapping = TextWrapping.Wrap });
        panel.Children.Add(tb); panel.Children.Add(buttons);
        w.Body = panel;
        w.Loaded += (_, _) => { tb.Focus(); tb.SelectAll(); };
        w.ShowDialog();
        return result;
    }

    void Disasm_DoubleClick(object s, MouseButtonEventArgs e)
    {
        if (Disasm.SelectedItem is DisasmLine l && l.Insn?.Target is int t) Navigate(t);
    }

    void ShowTab_Click(object s, RoutedEventArgs e)
    {
        if (s is MenuItem mi && int.TryParse(mi.Tag as string, out int k)) BottomTabs.SelectedIndex = k;
    }

    void About_Click(object s, RoutedEventArgs e) =>
        Dlg.Show(this,
            "Opcodex\n\nViewer / patcher for Python bytecode (.pyc), Python 3.8 - 3.15.\n" +
            "Pure C# marshal reader and writer, disassembler, assembler, structural code editor.",
            "About Opcodex", MessageBoxButton.OK, MessageBoxImage.Information);

    void ShowText(string title, string text, string dot)
    {
        var w = new ChromeWindow(title, true)
        {
            Width = 820, Height = 620, Owner = this, WindowStartupLocation = WindowStartupLocation.CenterOwner, CloseOnEscape = true,
        };
        var dock = new DockPanel();
        var top = new StackPanel { Orientation = Orientation.Horizontal };
        DockPanel.SetDock(top, Dock.Top);
        var copy = new Button { Content = "Copy all", Margin = new Thickness(6) };
        copy.Click += (_, _) => CopyText(text, "text");
        top.Children.Add(copy);
        if (dot != null)
        {
            var save = new Button { Content = "Save as Graphviz .dot...", Margin = new Thickness(0, 6, 6, 6) };
            save.Click += (_, _) =>
            {
                var dlg = new SaveFileDialog { Filter = "Graphviz (*.dot)|*.dot", FileName = "cfg.dot" };
                if (dlg.ShowDialog(w) == true) System.IO.File.WriteAllText(dlg.FileName, dot, new UTF8Encoding(false));
            };
            top.Children.Add(save);
        }
        dock.Children.Add(top);
        dock.Children.Add(AsmViewer(text));
        w.Body = dock;
        w.Show();
    }

    static TextBlock ImportBlock(string line)
    {
        var tb = new TextBlock { FontFamily = new FontFamily("Consolas"), Padding = new Thickness(2, 1, 2, 1) };
        void Kw(string t) => tb.Inlines.Add(new Run(t) { Foreground = B("#C586C0") });
        void Mod(string t) => tb.Inlines.Add(new Run(t) { Foreground = B("#4EC9B0") });
        void Plain(string t) => tb.Inlines.Add(new Run(t));

        string rest = line;
        bool from = rest.StartsWith("from ");
        if (!from && !rest.StartsWith("import ")) { Plain(line); return tb; }
        Kw(from ? "from" : "import"); Plain(" ");
        rest = rest.Substring(from ? 5 : 7);
        if (from)
        {
            int k = rest.IndexOf(" import ", StringComparison.Ordinal);
            string mod = k < 0 ? rest : rest.Substring(0, k);
            Mod(mod);
            if (k >= 0)
            {
                Plain(" "); Kw("import"); Plain(" ");
                var names = rest.Substring(k + 8).Split(new[] { ", " }, StringSplitOptions.None);
                for (int i = 0; i < names.Length; i++)
                {
                    if (i > 0) Plain(", ");
                    tb.Inlines.Add(new Run(names[i]) { Foreground = B(names[i] == "*" ? "#D4D4D4" : "#9CDCFE") });
                }
            }
        }
        else Mod(rest);
        return tb;
    }

    static List<TextBlock> ImportBlocks(IEnumerable<string> lines) => lines.Select(ImportBlock).ToList();

    static readonly Regex AsmTok = new(
        @"(?<c>;[^\n]*)" +
        @"|(?<s>'(?:\\.|[^'\\\n])*'|""(?:\\.|[^""\\\n])*"")" +
        @"|(?<o>\b0x[0-9A-Fa-f]+\b)" +
        @"|(?<b>\bB\d+\b)" +
        @"|(?<p>\((?:exception handler|exit|[a-z_]+)\))" +
        @"|(?<a>->)" +
        @"|(?<op>\b[A-Z][A-Z0-9_]{2,}\b)" +
        @"|(?<n>\b\d+\b)",
        RegexOptions.Compiled);

    static void AsmInlines(InlineCollection inl, string line)
    {
        int pos = 0;
        foreach (Match m in AsmTok.Matches(line))
        {
            if (m.Index > pos) inl.Add(new Run(line.Substring(pos, m.Index - pos)));
            var run = new Run(m.Value);
            if (m.Groups["c"].Success) { run.Foreground = B("#6A9955"); run.FontStyle = FontStyles.Italic; }
            else if (m.Groups["s"].Success) run.Foreground = B("#CE9178");
            else if (m.Groups["o"].Success || m.Groups["n"].Success) run.Foreground = B("#B5CEA8");
            else if (m.Groups["b"].Success) { run.Foreground = B("#4EC9B0"); run.FontWeight = FontWeights.SemiBold; }
            else if (m.Groups["p"].Success) run.Foreground = B("#858585");
            else if (m.Groups["a"].Success) run.Foreground = B("#C586C0");
            else run.Foreground = OpColor(m.Value);
            inl.Add(run);
            pos = m.Index + m.Length;
        }
        if (pos < line.Length) inl.Add(new Run(line.Substring(pos)));
    }

    RichTextBox AsmViewer(string text)
    {
        var lines = text.Replace("\r", "").Split('\n');
        var para = new Paragraph { Margin = new Thickness(0), LineHeight = 18, LineStackingStrategy = LineStackingStrategy.BlockLineHeight };
        int maxLen = 0;
        for (int i = 0; i < lines.Length; i++)
        {
            maxLen = Math.Max(maxLen, lines[i].Length);
            AsmInlines(para.Inlines, lines[i]);
            if (i < lines.Length - 1) para.Inlines.Add(new LineBreak());
        }
        return new RichTextBox
        {
            IsReadOnly = true, IsReadOnlyCaretVisible = true, BorderThickness = new Thickness(0),
            Background = (Brush)FindResource("Bg0"), Foreground = (Brush)FindResource("Fg"),
            FontFamily = new FontFamily("Consolas"), FontSize = 13, Padding = new Thickness(10, 8, 10, 8),
            HorizontalScrollBarVisibility = ScrollBarVisibility.Auto, VerticalScrollBarVisibility = ScrollBarVisibility.Auto,
            Document = new FlowDocument(para)
            {
                PagePadding = new Thickness(0), PageWidth = Math.Max(300, maxLen * CharWidth + 40),
                Foreground = (Brush)FindResource("Fg"), FontFamily = new FontFamily("Consolas"), FontSize = 13,
            },
        };
    }

    void Cfg_Click(object s, RoutedEventArgs e)
    {
        if (_pyc == null || _cur == null) { Log("CFG: no file loaded."); return; }
        if (StackEffectModel.IsModeled(_pyc.Opcodes.Minor))
        {
            var analysis = Decompiler.AnalyzeControlFlow(_cur, _pyc.Opcodes);
            ShowText($"Control flow graph - {_cur.QualName}", analysis.Dump(), analysis.ToDot());
            Log($"CFG of {_cur.QualName}: {analysis.Blocks.Count} block(s), {analysis.Edges.Count} edge(s), {analysis.Loops.Count} loop(s)");
            return;
        }
        var insns = _lines.Select(l => l.Insn).Where(i => i != null).ToList();
        var blocks = Cfg.Build(_cur, _pyc.Opcodes, insns);
        ShowText($"Control flow graph - {_cur.QualName}", Cfg.ToText(_cur, blocks), Cfg.ToDot(_cur, blocks));
        Log($"CFG of {_cur.QualName}: {blocks.Count} block(s)");
    }

    void ShowRefs(string title, List<(Instruction Insn, string Why)> refs)
    {
        var w = new ChromeWindow(title, true)
        {
            Width = 680, Height = 380, Owner = this, WindowStartupLocation = WindowStartupLocation.CenterOwner, CloseOnEscape = true,
        };
        var lb = new ListBox { FontFamily = new FontFamily("Consolas"), FontSize = 13 };
        foreach (var (i, why) in refs)
        {
            var tb = new TextBlock();
            AsmInlines(tb.Inlines, $"0x{i.Offset:X4}  {i.Name,-24} {i.Operand,-24} {why}");
            lb.Items.Add(tb);
        }
        lb.MouseDoubleClick += (_, _) =>
        {
            int k = lb.SelectedIndex;
            if (k < 0) return;
            Navigate(refs[k].Insn.Offset);
            w.Close();
        };
        w.Body = lb;
        w.Show();
    }

    void XRefs_Click(object s, RoutedEventArgs e)
    {
        if (_pyc == null || _cur == null) { Log("XRefs: no file loaded."); return; }
        if (Disasm.SelectedItem is not DisasmLine l || l.Insn == null) { StatusLeft.Text = "Select an instruction first"; return; }
        var insns = _lines.Select(x => x.Insn).Where(i => i != null).ToList();
        var refs = XRefs.For(insns, l.Insn);
        if (refs.Count == 0) { StatusLeft.Text = $"No cross-reference for {l.Offset}"; return; }
        ShowRefs($"Cross-references - {l.Offset} {l.Opcode} {l.Operand}".TrimEnd(), refs);
    }

    void RefList_DoubleClick(object s, MouseButtonEventArgs e)
    {
        if (_cur == null || s is not ListView lv || lv.SelectedItem is not Row row || row.Index is not int idx) return;
        char kind = lv == NameList ? 'n' : 'c';
        var refs = _lines.Where(l => l.Insn != null && l.Insn.RefKind == kind && l.Insn.RefIndex == idx)
                         .Select(l => (l.Insn, $"uses {(kind == 'n' ? "name" : "constant")} #{idx}")).ToList();
        if (refs.Count == 0) { StatusLeft.Text = "Not used by any instruction"; return; }
        if (refs.Count == 1) { Navigate(refs[0].Insn.Offset); return; }
        ShowRefs($"{(kind == 'n' ? "Name" : "Constant")} #{idx}: {row.Value}", refs);
    }

    bool PseudoVisible => CenterTabs.SelectedItem == PseudoTab;
    int _pseudoVer;
    bool _pseudoDirty;
    string _pseudoPre;

    void RefreshPseudo(string preSrc = null)
    {
        _pseudoVer++;
        _pseudoPre = preSrc;
        if (_pyc == null || _cur == null) { _pseudoDirty = false; Highlight(""); return; }
        if (!PseudoVisible) { _pseudoDirty = true; return; }
        _ = BuildPseudoAsync();
    }

    async Task BuildPseudoAsync()
    {
        _pseudoDirty = false;
        int ver = _pseudoVer;
        string src = _pseudoPre;
        _pseudoPre = null;
        if (src == null)
        {
            var pyc = _pyc;
            var pending = PendingPatches();
            int ci = CodeIdx(_cur);
            Highlight("# decompiling...");
            src = await Task.Run(() =>
            {
                try
                {
                    var pf = pending.Count == 0 ? pyc : PycFile.Parse(PatchService.Bake(pyc, pending), pyc.Path);
                    return Decompiler.Decompile(pf.AllCode[ci], pf.Opcodes);
                }
                catch (Exception ex) { return "# decompilation failed: " + ex.Message; }
            });
            if (ver != _pseudoVer) return;
        }
        Highlight(src);
    }

    void CenterTabs_SelectionChanged(object s, SelectionChangedEventArgs e)
    {
        if (FindBar == null || PseudoTab == null) return;
        if (!ReferenceEquals(e.OriginalSource, CenterTabs)) return;
        if (PseudoVisible && _pseudoDirty) _ = BuildPseudoAsync();
        if (FindBar.Visibility == Visibility.Visible) UpdateFind(false);
    }

    void Highlight(string src)
    {
        _pseudoFullSrc = src ?? "";
        src = PythonSourceFormatter.LimitForDisplay(_pseudoFullSrc);
        string norm = PythonSourceFormatter.Format((src ?? "").Replace("\r", ""));
        var lines = norm.Split('\n');

        _pseudoSrc = norm;
        _runs.Clear(); _runStarts.Clear();
        _pMatches.Clear(); _pCur = -1; _pLastStart = 0;
        PseudoOverlay.Children.Clear();

        var para = new Paragraph { Margin = new Thickness(0), LineHeight = 18, LineStackingStrategy = LineStackingStrategy.BlockLineHeight };
        void Add(Run r, int at) { para.Inlines.Add(r); _runs.Add(r); _runStarts.Add(at); }

        int abs = 0, maxLen = 0;
        var syntaxState = new PythonSyntaxState();
        for (int li = 0; li < lines.Length; li++)
        {
            string line = lines[li];
            maxLen = Math.Max(maxLen, line.Replace("\t", "    ").Length);
            foreach (PythonToken token in PythonSyntaxHighlighter.TokenizeLine(line, syntaxState))
            {
                var run = new Run(line.Substring(token.Start, token.Length));
                string color = token.Kind switch
                {
                    PythonTokenKind.Comment => "#6A9955",
                    PythonTokenKind.StringPrefix => "#569CD6",
                    PythonTokenKind.String => "#CE9178",
                    PythonTokenKind.Number => "#B5CEA8",
                    PythonTokenKind.Keyword => "#C586C0",
                    PythonTokenKind.Constant => "#569CD6",
                    PythonTokenKind.Builtin => "#4EC9B0",
                    PythonTokenKind.BuiltinFunction => "#DCDCAA",
                    PythonTokenKind.Variable or PythonTokenKind.Parameter or PythonTokenKind.Attribute => "#9CDCFE",
                    PythonTokenKind.FunctionName => "#DCDCAA",
                    PythonTokenKind.FunctionCall => "#DCDCAA",
                    PythonTokenKind.ClassName or PythonTokenKind.TypeName or PythonTokenKind.Decorator or
                        PythonTokenKind.ImportedName => "#4EC9B0",
                    PythonTokenKind.Operator or PythonTokenKind.Punctuation or PythonTokenKind.Interpolation => "#D4D4D4",
                    _ => null,
                };
                if (color != null) run.Foreground = B(color);
                Add(run, abs + token.Start);
            }
            if (li < lines.Length - 1) para.Inlines.Add(new LineBreak());
            abs += line.Length + 1;
        }

        double textW = Math.Max(200, maxLen * CharWidth + 40);
        Pseudo.Document = new FlowDocument(para)
        {
            PagePadding = new Thickness(0), PageWidth = textW,
            Foreground = (Brush)FindResource("Fg"), FontFamily = new FontFamily("Consolas"), FontSize = 13,
        };
        Pseudo.Width = textW + 10 + 14 + 4;
        PseudoLines.Text = string.Join("\n", Enumerable.Range(1, lines.Length));

        if (FindBar.Visibility == Visibility.Visible && PseudoVisible) FindPseudo(FindBox.Text, false);
    }

    static double? _charW;

    double CharWidth => _charW ??= new FormattedText("0000000000", System.Globalization.CultureInfo.InvariantCulture,
        FlowDirection.LeftToRight, new Typeface("Consolas"), 13, Brushes.White, VisualTreeHelper.GetDpi(this).PixelsPerDip).WidthIncludingTrailingWhitespace / 10;
}
