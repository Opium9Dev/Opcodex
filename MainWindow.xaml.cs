using System.Collections.ObjectModel;
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

public record DisasmLine(string Marker, string Offset, string Bytes, string Opcode, string Arg,
                         string Operand, string Comment, Brush OpBrush, Brush RowBrush,
                         Instruction Insn = null);
public record Row(object Index, string Type, string Value, string Refs);

public class PatchRec
{
    public PyCode Code;
    public int CodeIndex;
    public int Offset;
    public int FileOffset;
    public byte[] NewBytes;
    public DisasmLine Line;
    public string OffsetText = "", OrigText = "", NewText = "", Time = "";
    public PatchRec Clone() => (PatchRec)MemberwiseClone();
}

public class HistoryEntry
{
    public PyCode Code;
    public int CodeIndex;
    public int Offset;
    public PatchRec Before, After;

    public bool IsSnapshot;
    public string Label = "";
    public byte[] RawBefore, RawAfter;
    public List<PatchRec> RecsBefore;
}

public partial class MainWindow : Window
{
    readonly ObservableCollection<DisasmLine> _lines = new();
    readonly ObservableCollection<Row> _patches = new();
    readonly ObservableCollection<string> _log = new();

    readonly Dictionary<int, DisasmLine> _base = new();
    readonly List<HistoryEntry> _undo = new(), _redo = new();
    readonly Dictionary<PyCode, TreeViewItem> _nodes = new();
    readonly List<PatchRec> _patchRecs = new();

    PycFile _pyc;
    PyCode _cur;
    bool _suppressTree;

    static Dictionary<string, Brush> _brushCache;
    static Brush B(string hex)
    {
        _brushCache ??= new Dictionary<string, Brush>();
        if (_brushCache.TryGetValue(hex, out var b)) return b;
        b = (Brush)new BrushConverter().ConvertFrom(hex); b.Freeze();
        return _brushCache[hex] = b;
    }
    static readonly Brush Transp = Brushes.Transparent, Patched = B("#3B3000");

    public MainWindow()
    {
        InitializeComponent();
        StateChanged += OnState;
        PreviewKeyDown += (_, e) =>
        {
            if (!_loading) return;
            if (e.Key == Key.Escape) CancelLoad();
            e.Handled = true;
        };
        Closing += (_, _) => _loadCts?.Cancel();

        Activated += (_, _) => Root.BorderBrush = (Brush)FindResource("Accent");
        Deactivated += (_, _) => Root.BorderBrush = (Brush)FindResource("Line");
        Disasm.ItemsSource = _lines;
        PatchList.ItemsSource = _patches;
        LogList.ItemsSource = _log;
        Highlight("# Open a .pyc file (Ctrl+O) or drop it on this window.");
        Log("Ready. Supported: Python 3.8 - 3.15 (pure C# marshal reader, no Python needed).");
        UpdateStatus();

        var args = Environment.GetCommandLineArgs();
        if (args.Length > 1 && System.IO.File.Exists(args[1])) OpenFile(args[1]);
    }

    static Brush OpColor(string op) =>
        op.StartsWith("LOAD") || op.StartsWith("STORE") ? B("#9CDCFE") :
        op.Contains("JUMP") ? B("#C586C0") :
        op.StartsWith("CALL") || op.StartsWith("PRECALL") ? B("#DCDCAA") :
        op.StartsWith("RETURN") ? B("#F44747") :
        op.StartsWith("COMPARE") || op.StartsWith("BINARY") ? B("#4EC9B0") :
        op == "NOP" ? B("#808080") : B("#569CD6");

    static DisasmLine ToLine(Instruction i) =>
        new("", $"0x{i.Offset:X4}", DisasmExport.Hex(i.Bytes), i.Name, i.HasArg ? i.Arg.ToString() : "",
            i.Operand, i.Comment, OpColor(i.Name), Transp, i);

    void Log(string msg) { _log.Insert(0, $"[{DateTime.Now:HH:mm:ss}] {msg}"); }

    void UpdateStatus()
    {
        if (_pyc == null) { StatusRight.Text = "No file loaded"; return; }
        StatusRight.Text = $"Python {_pyc.VersionText} • magic {_pyc.MagicNumber} ({DisasmExport.Hex(_pyc.MagicBytes)}) • " +
                           $"{_lines.Count} instructions • {_patches.Count} patch(es)";
    }

    void Open_Click(object s, RoutedEventArgs e)
    {
        var dlg = new OpenFileDialog
        {
            Title = "Open .pyc",
            Filter = "Python bytecode (*.pyc)|*.pyc|All files (*.*)|*.*",
        };
        if (dlg.ShowDialog(this) == true) OpenFile(dlg.FileName);
    }

    void OpenCmd_Executed(object s, ExecutedRoutedEventArgs e) => Open_Click(s, e);
    void SaveCmd_Executed(object s, ExecutedRoutedEventArgs e) => Save_Click(s, e);

    void Window_Drop(object s, DragEventArgs e)
    {
        if (e.Data.GetData(DataFormats.FileDrop) is string[] files && files.Length > 0) OpenFile(files[0]);
    }

    sealed class LoadResult
    {
        public PycFile Pyc;
        public List<string> Imports;
        public List<FlagHit> Flags;
        public List<Instruction> RootInsns;
        public string RootSrc;
    }

    bool _loading;
    CancellationTokenSource _loadCts;

    void ShowLoading(string name)
    {
        LoadTitle.Text = "Loading " + name;
        LoadStage.Text = "Starting...";
        LoadBar.Value = 0; LoadPct.Text = "0 %";
        LoadCancel.IsEnabled = true;
        LoadOverlay.Visibility = Visibility.Visible;
        TopMenu.IsEnabled = false;
        Mouse.OverrideCursor = Cursors.AppStarting;
    }

    void HideLoading()
    {
        LoadOverlay.Visibility = Visibility.Collapsed;
        TopMenu.IsEnabled = true;
        Mouse.OverrideCursor = null;
    }

    void SetLoading(double fraction, string text)
    {
        fraction = Math.Max(0, Math.Min(1, fraction));
        LoadBar.Value = fraction * 100;
        LoadPct.Text = $"{fraction * 100:0} %";
        if (!string.IsNullOrEmpty(text)) { LoadStage.Text = text; StatusLeft.Text = text; }
    }

    void LoadCancel_Click(object s, RoutedEventArgs e) => CancelLoad();
    void CancelLoad() { if (_loading) { _loadCts?.Cancel(); LoadStage.Text = "Cancelling..."; } }

    static LoadResult LoadWorker(string path, IProgress<(double Pct, string Text)> prog, CancellationToken ct)
    {
        var clock = System.Diagnostics.Stopwatch.StartNew();
        void Report(double p, string t, bool force = false)
        {
            if (!force && clock.ElapsedMilliseconds < 40) return;
            clock.Restart();
            prog.Report((p, t));
        }

        Report(0, "Reading file...", true);
        long len = new System.IO.FileInfo(path).Length;
        var buf = new byte[len];
        using (var fs = new System.IO.FileStream(path, System.IO.FileMode.Open, System.IO.FileAccess.Read, System.IO.FileShare.Read, 1 << 16, System.IO.FileOptions.SequentialScan))
        {
            long off = 0;
            while (off < len)
            {
                ct.ThrowIfCancellationRequested();
                int n = fs.Read(buf, (int)off, (int)Math.Min(1 << 20, len - off));
                if (n <= 0) break;
                off += n;
                Report(0.08 * off / len, $"Reading file... {off / 1024} / {len / 1024} KB");
            }
            if (off < len) Array.Resize(ref buf, (int)off);
        }

        Report(0.08, "Parsing marshal data...", true);
        var pyc = PycFile.Parse(buf, path, f => Report(0.08 + 0.37 * f, $"Parsing marshal data... {f * 100:0} %"), ct);
        Report(0.45, $"Parsed: Python {pyc.VersionText}, {pyc.AllCode.Count} code object(s)", true);

        var impRecs = new List<ImportRec>();
        var imports = ComputeImports(pyc, (k, n) => Report(0.45 + 0.25 * k / Math.Max(1, n), $"Scanning imports... code object {k + 1} / {n}"), ct, impRecs);

        ct.ThrowIfCancellationRequested();
        Report(0.69, "Scanning behavior flags...", true);
        var flags = FlagScanner.Scan(pyc, impRecs, ct);

        ct.ThrowIfCancellationRequested();
        Report(0.70, "Disassembling the module code...", true);
        List<Instruction> insns;
        try { insns = Disassembler.Disassemble(pyc.Root, pyc.Opcodes); }
        catch (Exception) { insns = null; }
        ct.ThrowIfCancellationRequested();
        Report(0.78, "Decompiling the module code...", true);
        string src = Decompiler.Decompile(pyc.Root, pyc.Opcodes);
        Report(0.90, "Building the code object tree...", true);
        return new LoadResult { Pyc = pyc, Imports = imports, Flags = flags, RootInsns = insns, RootSrc = src };
    }

    async void OpenFile(string path)
    {
        if (_loading) { StatusLeft.Text = "A file is already loading..."; return; }
        _loading = true;
        _loadCts = new CancellationTokenSource();
        var ct = _loadCts.Token;
        string name = System.IO.Path.GetFileName(path);
        ShowLoading(name);
        var prog = new Progress<(double Pct, string Text)>(p => SetLoading(p.Pct, p.Text));
        try
        {
            var res = await Task.Run(() => LoadWorker(path, prog, ct), ct);
            ct.ThrowIfCancellationRequested();

            LoadCancel.IsEnabled = false;
            var pyc = res.Pyc;
            _pyc = pyc;
            _cur = null;
            _patchRecs.Clear(); _patches.Clear(); _base.Clear(); _lines.Clear();
            _undo.Clear(); _redo.Clear(); _nodes.Clear();
            Title = $"Opcodex - {name}";

            FillHeader();
            ImportsList.ItemsSource = ImportBlocks(res.Imports);
            ApplyFlags(res.Flags);
            var module = await BuildTreeAsync();
            LoadCode(pyc.Root, res.RootInsns, res.RootSrc);
            _suppressTree = true;
            if (module != null) module.IsSelected = true;
            _suppressTree = false;

            Log($"File loaded: {name} (Python {pyc.VersionText}, {pyc.AllCode.Count} code object(s))");
            if (pyc.TrailingBytes > 0) Log($"Warning: {pyc.TrailingBytes} trailing byte(s) after the marshal data.");
        }
        catch (OperationCanceledException)
        {
            Log($"Open cancelled: {name}");
            StatusLeft.Text = "Open cancelled";
        }
        catch (Exception ex)
        {
            Log($"Open failed: {name}: {ex.Message}");
            HideLoading();
            Dlg.Show(this, ex.Message, "Opcodex - cannot open file", MessageBoxButton.OK, MessageBoxImage.Error);
        }
        finally
        {
            HideLoading();
            _loading = false;
            UpdateStatus();
        }
    }

    void Export_Click(object s, RoutedEventArgs e)
    {
        if (_pyc == null) { Log("Export: no file loaded."); return; }
        var dlg = new SaveFileDialog
        {
            Title = "Export disassembly",
            Filter = "Text file (*.txt)|*.txt",
            FileName = System.IO.Path.GetFileNameWithoutExtension(_pyc.Path) + ".dis.txt",
        };
        if (dlg.ShowDialog(this) != true) return;
        try
        {
            System.IO.File.WriteAllText(dlg.FileName, DisasmExport.Format(_pyc), new UTF8Encoding(false));
            Log($"Disassembly exported to {dlg.FileName}");
        }
        catch (Exception ex) { Log($"Export failed: {ex.Message}"); Dlg.Show(this, ex.Message, "Opcodex", MessageBoxButton.OK, MessageBoxImage.Error); }
    }

    void Save_Click(object s, RoutedEventArgs e)
    {
        if (_pyc == null) { Log("Save: no file loaded."); return; }
        var dlg = new SaveFileDialog
        {
            Title = "Save patched .pyc",
            Filter = "Python bytecode (*.pyc)|*.pyc",
            FileName = System.IO.Path.GetFileNameWithoutExtension(_pyc.Path) + ".patched.pyc",
            InitialDirectory = System.IO.Path.GetDirectoryName(_pyc.Path),
        };
        if (dlg.ShowDialog(this) != true) return;
        try
        {
            var buf = (byte[])_pyc.Raw.Clone();
            int real = 0, simulated = 0;
            foreach (var r in _patchRecs)
            {
                if (r.NewBytes == null) { simulated++; continue; }
                Buffer.BlockCopy(r.NewBytes, 0, buf, r.FileOffset, r.NewBytes.Length);
                real++;
            }
            System.IO.File.WriteAllBytes(dlg.FileName, buf);
            Log($"Saved {dlg.FileName} ({real} patch(es) written)");
            if (simulated > 0) Log($"Warning: {simulated} simulated patch(es) were NOT written (instruction assembly is not implemented yet).");
        }
        catch (Exception ex) { Log($"Save failed: {ex.Message}"); Dlg.Show(this, ex.Message, "Opcodex", MessageBoxButton.OK, MessageBoxImage.Error); }
    }

    void FillHeader()
    {
        var p = _pyc;
        var rows = new List<Row>
        {
            new("File", "", p.Path, ""),
            new("Size", "", $"{p.Raw.Length} bytes", ""),
            new("Magic bytes", "", DisasmExport.Hex(p.MagicBytes), ""),
            new("Magic number", "", $"{p.MagicNumber} (0x{p.MagicNumber:X})", ""),
            new("Python version", "", p.VersionText, ""),
            new("Flags", "", $"0x{p.Flags:X8}  " + (p.HashBased
                ? "hash-based, " + (p.CheckSource ? "check_source" : "unchecked")
                : "timestamp-based") + ((p.Flags & ~3u) != 0 ? "  (unknown bits set)" : ""), ""),
        };
        if (p.HashBased)
            rows.Add(new("Source hash", "", DisasmExport.Hex(p.SourceHash).Replace(" ", ""), ""));
        else
        {
            rows.Add(new("Source mtime", "", $"{p.Timestamp}  ({DateTimeOffset.FromUnixTimeSeconds(p.Timestamp).UtcDateTime:yyyy-MM-dd HH:mm:ss} UTC)", ""));
            rows.Add(new("Source size", "", $"{p.SourceSize} bytes", ""));
        }
        rows.Add(new("Marshal data offset", "", $"0x{PycFile.HeaderSize:X}", ""));
        rows.Add(new("Code objects", "", p.AllCode.Count.ToString(), ""));
        rows.Add(new("Root code", "", $"{p.Root.Name}  ({p.Root.Filename})", ""));
        HeaderList.ItemsSource = rows;
    }

    System.Windows.Shapes.Path MakeIcon(string key, string color) => new()
    {
        Style = (Style)FindResource("Ico"),
        Data = (Geometry)FindResource(key),
        Stroke = B(color), Width = 12, Height = 12,
    };

    TreeViewItem MakeNode(string text, string iconKey, string color, object tag)
    {
        var sp = new StackPanel { Orientation = Orientation.Horizontal };
        sp.Children.Add(MakeIcon(iconKey, color));
        sp.Children.Add(new TextBlock { Text = text });
        return new TreeViewItem { Header = sp, Tag = tag };
    }

    TreeViewItem CodeNode(PyCode c, int depth)
    {
        var n = c.IsClassBody
            ? MakeNode("class " + c.Name, "IcoDiamond", "#4EC9B0", c)
            : MakeNode(c.Name, "IcoCode", "#DCDCAA", c);
        n.IsExpanded = depth < 2;
        _nodes[c] = n;
        foreach (var ch in c.Children) n.Items.Add(CodeNode(ch, depth + 1));
        return n;
    }

    async Task<TreeViewItem> BuildTreeAsync()
    {
        CodeTree.Items.Clear();
        _nodes.Clear();
        var all = _pyc.AllCode;
        int total = Math.Max(1, all.Count);
        var clock = System.Diagnostics.Stopwatch.StartNew();

        for (int k = 0; k < all.Count; k++)
        {
            var c = all[k];
            _nodes[c] = c.IsClassBody
                ? MakeNode("class " + c.Name, "IcoDiamond", "#4EC9B0", c)
                : MakeNode(c.Name, "IcoCode", "#DCDCAA", c);
            if (clock.ElapsedMilliseconds >= 30)
            {
                SetLoading(0.90 + 0.07 * k / total, $"Building the code object tree... {k + 1} / {all.Count}");
                await System.Windows.Threading.Dispatcher.Yield(System.Windows.Threading.DispatcherPriority.Background);
                clock.Restart();
            }
        }

        var linked = new HashSet<PyCode>();
        for (int k = 0; k < all.Count; k++)
        {
            var c = all[k];
            foreach (var ch in c.Children)
                if (_nodes.TryGetValue(ch, out var cn) && linked.Add(ch)) _nodes[c].Items.Add(cn);
            if (clock.ElapsedMilliseconds >= 30)
            {
                SetLoading(0.97 + 0.03 * k / total, "Linking code objects...");
                await System.Windows.Threading.Dispatcher.Yield(System.Windows.Threading.DispatcherPriority.Background);
                clock.Restart();
            }
        }

        void Expand(PyCode c, int depth)
        {
            if (depth >= 2 || !_nodes.TryGetValue(c, out var n)) return;
            n.IsExpanded = true;
            foreach (var ch in c.Children) Expand(ch, depth + 1);
        }
        Expand(_pyc.Root, 0);

        var root = MakeNode(System.IO.Path.GetFileName(_pyc.Path), "IcoPackage", "#9CDCFE", null);
        root.IsExpanded = true;
        _nodes.TryGetValue(_pyc.Root, out var module);
        if (module != null) root.Items.Add(module);
        CodeTree.Items.Add(root);
        SetLoading(1.0, "Done");
        return module;
    }

    void BuildTree()
    {
        CodeTree.Items.Clear();
        var root = MakeNode(System.IO.Path.GetFileName(_pyc.Path), "IcoPackage", "#9CDCFE", null);
        root.IsExpanded = true;
        var module = CodeNode(_pyc.Root, 0);
        root.Items.Add(module);
        CodeTree.Items.Add(root);

        LoadCode(_pyc.Root);
        _suppressTree = true;
        module.IsSelected = true;
        _suppressTree = false;
    }

    void CodeTree_SelectedItemChanged(object s, RoutedPropertyChangedEventArgs<object> e)
    {
        if (_suppressTree) return;
        if (e.NewValue is TreeViewItem ti && ti.Tag is PyCode c) LoadCode(c);
    }

    void LoadCode(PyCode co, List<Instruction> pre = null, string preSrc = null, bool refreshPseudo = true)
    {
        _cur = co;
        _base.Clear();

        List<Instruction> insns = pre;
        if (insns == null)
        {
            try { insns = Disassembler.Disassemble(co, _pyc.Opcodes); }
            catch (Exception ex) { Log($"Disassembly failed for {co.Name}: {ex.Message}"); insns = new List<Instruction>(); }
        }

        Disasm.ItemsSource = null;
        _lines.Clear();
        foreach (var i in insns) { var l = ToLine(i); _base[i.Offset] = l; _lines.Add(l); }

        foreach (var r in _patchRecs.Where(r => r.Code == co))
        {
            int idx = IndexOfOffset(r.Offset);
            if (idx >= 0) _lines[idx] = r.Line;
        }
        Disasm.ItemsSource = _lines;

        FillProps(co);
        FillTables(co, insns);
        if (refreshPseudo)
        {
            RefreshPseudo(preSrc);
        }
        else
        {
            _pseudoVer++;
            _pseudoPre = null;
            _pseudoDirty = true;
        }
        UpdateStatus();
        StatusLeft.Text = $"{co.QualName}: {insns.Count} instructions";
        if (_lines.Count > 0) Disasm.SelectedIndex = 0;
        else { InspTitle.Text = "No instruction selected"; InspBytes.Text = ""; }
    }

    void FillProps(PyCode c)
    {
        string flags = $"0x{c.Flags:X}" + (c.FlagsText().Length > 0 ? "  " + c.FlagsText() : "");
        string Tup(string[] a) => a.Length == 0 ? "()" : "(" + string.Join(", ", a.Select(PyObj.StrRepr)) + (a.Length == 1 ? ",)" : ")");
        var rows = new List<Row>
        {
            new("name", "", c.Name, ""), new("qualname", "", c.QualName, ""), new("filename", "", c.Filename, ""),
            new("argcount", "", c.ArgCount.ToString(), ""),
            new("posonlyargcount", "", c.PosOnlyArgCount.ToString(), ""),
            new("kwonlyargcount", "", c.KwOnlyArgCount.ToString(), ""),
        };
        if (c.NLocals >= 0) rows.Add(new("nlocals", "", c.NLocals.ToString(), ""));
        rows.Add(new("stacksize", "", c.StackSize.ToString(), ""));
        rows.Add(new("firstlineno", "", c.FirstLineNo.ToString(), ""));
        rows.Add(new("flags", "", flags, ""));
        rows.Add(new("varnames", "", Tup(c.VarNames), ""));
        rows.Add(new("freevars", "", Tup(c.FreeVars), ""));
        rows.Add(new("cellvars", "", Tup(c.CellVars), ""));
        rows.Add(new("code size", "", $"{c.Code.Data.Length} bytes @ file 0x{c.Code.FileOffset:X}", ""));
        PropList.ItemsSource = rows;
    }

    static string RefText(List<int> offs)
    {
        if (offs == null || offs.Count == 0) return "-";
        string s = string.Join(", ", offs.Take(4).Select(o => $"0x{o:X}"));
        return offs.Count > 4 ? s + $" (+{offs.Count - 4})" : s;
    }

    void FillTables(PyCode c, List<Instruction> insns)
    {
        var constRefs = new Dictionary<int, List<int>>();
        var nameRefs = new Dictionary<int, List<int>>();
        var nameKind = new Dictionary<int, string>();
        foreach (var i in insns)
        {
            if (i.RefKind == 'c')
            {
                if (!constRefs.TryGetValue(i.RefIndex, out var l)) constRefs[i.RefIndex] = l = new List<int>();
                l.Add(i.Offset);
            }
            else if (i.RefKind == 'n')
            {
                if (!nameRefs.TryGetValue(i.RefIndex, out var l)) nameRefs[i.RefIndex] = l = new List<int>();
                l.Add(i.Offset);
                if (!nameKind.ContainsKey(i.RefIndex))
                    nameKind[i.RefIndex] = i.Name.Contains("GLOBAL") ? "global" :
                                           i.Name.Contains("ATTR") || i.Name.Contains("METHOD") ? "attr" :
                                           i.Name.Contains("IMPORT") ? "import" : "name";
            }
        }

        var consts = new List<Row>();
        var strings = new List<Row>();
        for (int k = 0; k < c.Consts.Count; k++)
        {
            var o = c.Consts[k];
            constRefs.TryGetValue(k, out var refs);
            consts.Add(new Row(k, o.TypeName, PyObj.Trunc(o.Repr(), 300), RefText(refs)));
            if (o is PyStr ps)
            {
                string r = PyObj.StrRepr(ps.Value);
                strings.Add(new Row(k, "str", PyObj.Trunc(r.Substring(1, r.Length - 2), 300), RefText(refs)));
            }
        }
        ConstList.ItemsSource = consts;
        StringList.ItemsSource = strings;

        var names = new List<Row>();
        for (int k = 0; k < c.Names.Length; k++)
        {
            nameRefs.TryGetValue(k, out var refs);
            names.Add(new Row(k, nameKind.TryGetValue(k, out var kind) ? kind : "name", c.Names[k], RefText(refs)));
        }
        NameList.ItemsSource = names;
    }

    static PyObj ConstOf(Instruction i, PyCode c)
    {
        if (i == null) return null;
        if (i.RefKind == 'c' && i.RefIndex >= 0 && i.RefIndex < c.Consts.Count) return c.Consts[i.RefIndex];
        if (i.Name == "LOAD_SMALL_INT") return new PyInt(i.Arg);
        return null;
    }

    void FillImports()
    {
        var recs = new List<ImportRec>();
        ImportsList.ItemsSource = ImportBlocks(ComputeImports(_pyc, null, default, recs));
        ApplyFlags(FlagScanner.Scan(_pyc, recs, default));      // flags recalculés après patch / rebuild
    }

    static List<string> ComputeImports(PycFile pyc, Action<int, int> progress, CancellationToken ct, List<ImportRec> recs = null)
    {
        var found = new List<string>();
        var seen = new HashSet<string>();
        int n = pyc.AllCode.Count;
        for (int ci = 0; ci < n; ci++)
        {
            ct.ThrowIfCancellationRequested();
            progress?.Invoke(ci, n);
            var c = pyc.AllCode[ci];
            var ins = Disassembler.Disassemble(c, pyc.Opcodes);
            for (int k = 0; k < ins.Count; k++)
            {
                if (ins[k].Name != "IMPORT_NAME" || ins[k].RefKind != 'n') continue;
                int ni = ins[k].RefIndex;
                string mod = ni >= 0 && ni < c.Names.Length ? c.Names[ni] : "?";
                var fromList = k >= 1 ? ConstOf(ins[k - 1], c) : null;
                var level = k >= 2 ? ConstOf(ins[k - 2], c) as PyInt : null;
                string dots = level != null && level.Value > 0 ? new string('.', (int)level.Value) : "";
                string line;
                if (fromList is PyTuple t && t.Items.Count > 0)
                    line = $"from {dots}{mod} import " + string.Join(", ", t.Items.Select(x => x is PyStr s ? s.Value : x.Repr()));
                else line = $"import {dots}{mod}";
                if (seen.Add(line))
                {
                    found.Add(line);
                    recs?.Add(new ImportRec(line, mod,
                        fromList is PyTuple ft ? ft.Items.OfType<PyStr>().Select(x => x.Value).ToArray() : Array.Empty<string>(), c));
                }
            }
        }
        return found;
    }

    void Disasm_SelectionChanged(object s, SelectionChangedEventArgs e)
    {
        if (Disasm.SelectedItem is not DisasmLine l) return;
        InspTitle.Text = $"{l.Offset}  {l.Opcode} {l.Arg} {l.Operand}".TrimEnd();
        InspBytes.Text = $"bytes: {l.Bytes}";
        StatusLeft.Text = $"Selection: {l.Offset}";
    }

    PatchRec FindRec(PyCode c, int off) => _patchRecs.Find(r => r.Code == c && r.Offset == off);

    int IndexOfOffset(int off)
    {
        for (int i = 0; i < _lines.Count; i++)
            if (_lines[i].Insn != null && _lines[i].Insn.Offset == off) return i;
        return -1;
    }

    void SetRec(PyCode c, int off, PatchRec rec)
    {
        int i = _patchRecs.FindIndex(r => r.Code == c && r.Offset == off);
        if (rec != null) { rec.Code = c; rec.CodeIndex = CodeIdx(c); }
        if (rec == null) { if (i >= 0) _patchRecs.RemoveAt(i); }
        else if (i >= 0) _patchRecs[i] = rec;
        else _patchRecs.Add(rec);

        RefreshPatchList();

        if (c == _cur)
        {
            int idx = IndexOfOffset(off);
            if (idx >= 0)
            {
                if (rec != null) _lines[idx] = rec.Line;
                else if (_base.TryGetValue(off, out var orig)) _lines[idx] = orig;
            }
            RefreshPseudo();
        }
        UpdateStatus();
    }

    void SelectOffset(int off)
    {
        int idx = IndexOfOffset(off);
        if (idx < 0) return;
        Disasm.SelectedIndex = idx;
        Disasm.ScrollIntoView(_lines[idx]);
    }

    void DoPatch(int idx, DisasmLine nl, byte[] newBytes)
    {
        var old = _lines[idx];
        if (old.Insn == null || _cur == null) return;
        int off = old.Insn.Offset;
        var orig = _base.TryGetValue(off, out var o) ? o : old;
        var h = new HistoryEntry
        {
            Code = _cur, CodeIndex = CodeIdx(_cur), Offset = off, Before = FindRec(_cur, off),
            After = new PatchRec
            {
                Code = _cur, CodeIndex = CodeIdx(_cur), Offset = off, FileOffset = old.Insn.FileOffset, NewBytes = newBytes, Line = nl,
                OffsetText = old.Offset, OrigText = $"{orig.Opcode} {orig.Arg}".Trim(),
                NewText = $"{nl.Opcode} {nl.Arg}".Trim(), Time = DateTime.Now.ToString("HH:mm:ss"),
            },
        };
        _undo.Add(h);
        _redo.Clear();
        SetRec(h.Code, h.Offset, h.After);
        Log($"Patch {old.Offset}: {orig.Opcode} → {nl.Opcode}" + (newBytes == null ? " (simulated, will not be saved)" : ""));
        SelectOffset(off);
    }

    void GoTo(HistoryEntry h)
    {
        var code = CodeAt(h.CodeIndex);
        if (code != null && code != _cur && _nodes.TryGetValue(code, out var node)) node.IsSelected = true;
    }

    static string Describe(HistoryEntry h, PatchRec state)
    {
        string off = $"0x{h.Offset:X4}";
        return state == null ? $"{off}: patch removed" : $"{off}: {state.OrigText} → {state.NewText}";
    }

    void Undo_Click(object s, RoutedEventArgs e)
    {
        if (_undo.Count == 0) { StatusLeft.Text = "Nothing to undo"; return; }
        var h = _undo[^1];
        _undo.RemoveAt(_undo.Count - 1);
        _redo.Add(h);
        if (h.IsSnapshot)
        {
            ApplySnapshot(h.RawBefore, h.RecsBefore, h.CodeIndex, h.Offset);
            Log("Undo " + h.Label);
            return;
        }
        GoTo(h);
        SetRec(CodeAt(h.CodeIndex), h.Offset, h.Before?.Clone());
        Log("Undo " + Describe(h, h.After));
        SelectOffset(h.Offset);
    }

    void Redo_Click(object s, RoutedEventArgs e)
    {
        if (_redo.Count == 0) { StatusLeft.Text = "Nothing to redo"; return; }
        var h = _redo[^1];
        _redo.RemoveAt(_redo.Count - 1);
        _undo.Add(h);
        if (h.IsSnapshot)
        {
            ApplySnapshot(h.RawAfter, null, h.CodeIndex, h.Offset);
            Log("Redo " + h.Label);
            return;
        }
        GoTo(h);
        SetRec(CodeAt(h.CodeIndex), h.Offset, h.After?.Clone());
        Log("Redo " + Describe(h, h.After));
        SelectOffset(h.Offset);
    }

    void UndoCmd_Executed(object s, ExecutedRoutedEventArgs e) => Undo_Click(s, e);
    void RedoCmd_Executed(object s, ExecutedRoutedEventArgs e) => Redo_Click(s, e);

    void Nop_Click(object s, RoutedEventArgs e)
    {
        int i = Disasm.SelectedIndex; if (i < 0 || _pyc == null) return;
        var o = _lines[i];
        if (o.Insn == null) return;
        if (!_pyc.Opcodes.TryGetOpcode("NOP", out int nop)) { Log("NOP opcode not found for this Python version."); return; }

        int words = 1 + o.Insn.Caches;
        var bytes = new byte[words * 2];
        for (int k = 0; k < words; k++) bytes[2 * k] = (byte)nop;
        string hex = DisasmExport.Hex(new[] { (byte)nop, (byte)0 }) + (words > 1 ? $" x{words}" : "");
        if (_cur?.Code != null && _cur.Code.SharedRefs > 0)
            Log("Warning: this co_code payload is shared with another code object.");
        DoPatch(i, new DisasmLine("patched", o.Offset, hex, "NOP", "", "", "; patched", OpColor("NOP"), Patched, o.Insn), bytes);
    }

    void Apply_Click(object s, RoutedEventArgs e)
    {
        if (_pyc == null || _cur == null) { Log("Patch: no file loaded."); return; }
        int i = Disasm.SelectedIndex;
        if (i < 0 || _lines[i].Insn == null) { StatusLeft.Text = "Select an instruction first"; return; }
        ApplyText(i, PatchBox.Text, StructOp.Replace);
    }

    void Stub_Click(object s, RoutedEventArgs e)
    {
        object name = (s as MenuItem)?.Header ?? (s as Button)?.Tag;
        Log($"Action: {name} (not implemented)");
        StatusLeft.Text = $"{name}";
    }

    void Quit_Click(object s, RoutedEventArgs e) => Close();
    void Min_Click(object s, RoutedEventArgs e) => WindowState = WindowState.Minimized;
    void Max_Click(object s, RoutedEventArgs e) =>
        WindowState = WindowState == WindowState.Maximized ? WindowState.Normal : WindowState.Maximized;

    void OnState(object s, EventArgs e)
    {
        bool max = WindowState == WindowState.Maximized;
        BorderThickness = max ? SystemParameters.WindowResizeBorderThickness : new Thickness(0);
        MaxIcon.Data = Geometry.Parse(max ? "M2.5,0.5 H9.5 V7.5 M0.5,2.5 H7.5 V9.5 H0.5 Z" : "M0.5,0.5 H9.5 V9.5 H0.5 Z");
    }
}
