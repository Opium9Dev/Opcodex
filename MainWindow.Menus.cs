using System.Text;
using System.Windows;
using System.Windows.Controls;
using System.Windows.Input;
using System.Windows.Media;
using Microsoft.Win32;
using Opcodex.Pyc;

namespace Opcodex;

public partial class MainWindow
{

    void CopyText(string text, string what)
    {
        for (int attempt = 0; attempt < 5; attempt++)
        {
            try
            {
                Clipboard.SetDataObject(text ?? "", true);
                StatusLeft.Text = $"Copied {what}";
                return;
            }
            catch (System.Runtime.InteropServices.COMException) { Thread.Sleep(30); }
            catch (Exception ex) { StatusLeft.Text = "Clipboard error: " + ex.Message; return; }
        }
        StatusLeft.Text = "Clipboard is busy, try again";
    }

    bool _ctxOnRow;

    void Disasm_PreviewRightDown(object s, MouseButtonEventArgs e)
    {
        DependencyObject d = e.OriginalSource as DependencyObject;
        while (d != null && d is not ListViewItem)
            d = d is Visual || d is System.Windows.Media.Media3D.Visual3D ? VisualTreeHelper.GetParent(d) : LogicalTreeHelper.GetParent(d);
        _ctxOnRow = d is ListViewItem;

        if (d is ListViewItem it && !it.IsSelected) { Disasm.SelectedItems.Clear(); it.IsSelected = true; }
    }

    void Disasm_ContextMenuOpening(object s, ContextMenuEventArgs e)
    {
        if (!_ctxOnRow || _pyc == null || Disasm.SelectedItem == null) e.Handled = true;
    }

    void DisasmMenu_Opened(object s, RoutedEventArgs e)
    {
        var l = Disasm.SelectedItem as DisasmLine;
        bool has = l?.Insn != null;
        CmGoto.IsEnabled = has && l.Insn.Target != null;
        CmInvert.IsEnabled = has && (l.Opcode.Contains("JUMP_IF") || l.Opcode.StartsWith("POP_JUMP"));
    }

    static string LineText(DisasmLine l)
    {
        string t = $"{l.Offset}  {l.Bytes,-5}  {l.Opcode,-24} {l.Arg,-6} {l.Operand}";
        if (!string.IsNullOrEmpty(l.Comment)) t += "  " + l.Comment;
        return t.TrimEnd();
    }

    List<DisasmLine> SelectedLines() =>
        Disasm.SelectedItems.Cast<DisasmLine>().OrderBy(l => l.Insn?.Offset ?? 0).ToList();

    void CopyInsn_Click(object s, RoutedEventArgs e)
    {
        var sel = SelectedLines();
        if (sel.Count == 0) return;
        CopyText(string.Join("\r\n", sel.Select(LineText)), sel.Count == 1 ? "instruction" : $"{sel.Count} instructions");
    }

    void CopyField_Click(object s, RoutedEventArgs e)
    {
        var sel = SelectedLines();
        if (sel.Count == 0 || s is not MenuItem mi) return;
        string tag = mi.Tag as string ?? "";
        static string Field(DisasmLine l, string t) => t switch
        {
            "opcode" => l.Opcode, "arg" => l.Arg, "operand" => l.Operand, "offset" => l.Offset, "bytes" => l.Bytes, _ => "",
        };
        CopyText(string.Join("\r\n", sel.Select(l => Field(l, tag))), tag);
    }

    void CopyRoutine_Click(object s, RoutedEventArgs e)
    {
        if (_cur == null) return;
        var sb = new StringBuilder();
        sb.AppendLine($"; ===== {_cur.QualName} (file {PyObj.StrRepr(_cur.Filename)}, line {_cur.FirstLineNo}) =====");
        foreach (var l in _lines) sb.AppendLine(LineText(l));
        CopyText(sb.ToString(), $"routine {_cur.QualName} ({_lines.Count} instructions)");
    }

    void CopyFileDis_Click(object s, RoutedEventArgs e)
    {
        if (_pyc == null) return;
        try
        {
            var pending = PendingPatches();
            var pf = pending.Count == 0 ? _pyc : PycFile.Parse(PatchService.Bake(_pyc, pending), _pyc.Path);
            CopyText(DisasmExport.Format(pf), "whole file disassembly");
        }
        catch (Exception ex) { StatusLeft.Text = "Copy failed: " + ex.Message; }
    }

    void CmGoto_Click(object s, RoutedEventArgs e)
    {
        if (Disasm.SelectedItem is DisasmLine l && l.Insn?.Target is int t) Navigate(t);
    }

    void DeleteInsn_Click(object s, RoutedEventArgs e)
    {
        int i = Disasm.SelectedIndex;
        if (_pyc == null || _cur == null || i < 0 || _lines[i].Insn == null) { StatusLeft.Text = "Select an instruction first"; return; }
        DoStructural(StructOp.Delete, _lines[i].Insn.Offset, null, $"Delete instruction {_lines[i].Offset}");
    }

    void PseudoCopy_Click(object s, RoutedEventArgs e)
    {
        string t = Pseudo.Selection.Text;
        if (string.IsNullOrEmpty(t)) { StatusLeft.Text = "Nothing selected"; return; }
        CopyText(t.Replace("\r\n", "\n").Replace("\n", "\r\n"), "selection");
    }

    void PseudoSelectAll_Click(object s, RoutedEventArgs e) { Pseudo.Focus(); Pseudo.SelectAll(); }

    void PseudoCopyAll_Click(object s, RoutedEventArgs e)
    {
        string source = _pseudoFullSrc.Replace("\r\n", "\n").Replace('\r', '\n');
        CopyText(source.Replace("\n", "\r\n"), $"source ({source.Split('\n').Length} lines)");
    }

    async void ExportSource_Click(object s, RoutedEventArgs e)
    {
        if (_pyc == null) { Log("Export source: no file loaded."); return; }
        if (_loading) return;
        var dlg = new SaveFileDialog
        {
            Title = "Export source",
            Filter = "Python source (*.py)|*.py|All files (*.*)|*.*",
            FileName = System.IO.Path.GetFileNameWithoutExtension(_pyc.Path) + ".decompiled.py",
        };
        if (dlg.ShowDialog(this) != true) return;

        string target = dlg.FileName, name = System.IO.Path.GetFileName(_pyc.Path);
        var pyc = _pyc;
        var pending = PendingPatches();

        _loading = true;
        ShowLoading("Exporting source");
        LoadCancel.IsEnabled = false;
        SetLoading(0.25, "Decompiling all code objects...");
        try
        {
            int count = await Task.Run(() =>
            {
                var pf = pending.Count == 0 ? pyc : PycFile.Parse(PatchService.Bake(pyc, pending), pyc.Path);
                string src = PythonSourceFormatter.Format(
                    Decompiler.Decompile(pf.Root, pf.Opcodes).Replace("\r", ""));
                if (Decompiler.HasIncompleteOutput(src))
                    throw new InvalidOperationException("The source contains incomplete bytecode reconstructions and was not exported.");
                string text = $"# Decompiled from {name} (Python {pyc.VersionText}) by Opcodex\n" +
                              "# Reconstructed from bytecode: it can differ from the original source.\n\n" + src + "\n";
                System.IO.File.WriteAllText(target, text, new UTF8Encoding(false));
                return src.Split('\n').Length;
            });
            SetLoading(1, "Done");
            Log($"Source exported to {target} ({count} lines)");
            StatusLeft.Text = $"Source exported: {count} lines";
        }
        catch (Exception ex)
        {
            Log($"Export source failed: {ex.Message}");
            HideLoading();
            Dlg.Show(this, ex.Message, "Opcodex - export source", MessageBoxButton.OK, MessageBoxImage.Error);
        }
        finally
        {
            HideLoading();
            _loading = false;
        }
    }
}
