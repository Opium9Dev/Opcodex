using System.Windows;
using System.Windows.Controls;
using System.Windows.Documents;
using System.Windows.Input;
using System.Windows.Media;
using System.Windows.Shapes;
using Opcodex.Pyc;

namespace Opcodex;

public partial class MainWindow
{

    string _pseudoSrc = "";
    string _pseudoFullSrc = "";
    readonly List<Run> _runs = new();
    readonly List<int> _runStarts = new();
    readonly List<(int Start, int Len)> _pMatches = new();
    int _pCur = -1;
    int _pLastStart;

    const int MaxDrawnMatches = 500;
    static Brush HlAll => B("#66E8B400");
    static Brush HlCur => B("#CCFF8C00");
    static Brush FindBad => B("#F44747");

    void ShowFindBar()
    {
        if (_loading) return;
        FindBar.Visibility = Visibility.Visible;

        if (PseudoVisible)
        {
            string sel = Pseudo.Selection.Text;
            if (!string.IsNullOrEmpty(sel) && sel.Length <= 120 && sel.IndexOfAny(new[] { '\r', '\n' }) < 0)
                FindBox.Text = sel;
        }
        FindBox.Focus();
        FindBox.SelectAll();
        UpdateFind(true);
    }

    void HideFindBar()
    {
        FindBar.Visibility = Visibility.Collapsed;
        PseudoOverlay.Children.Clear();
        if (PseudoVisible) Pseudo.Focus(); else Disasm.Focus();
    }

    void FindClose_Click(object s, RoutedEventArgs e) => HideFindBar();
    void FindNext_Click(object s, RoutedEventArgs e) => FindStep(+1);
    void FindPrev_Click(object s, RoutedEventArgs e) => FindStep(-1);
    void FindBox_TextChanged(object s, TextChangedEventArgs e) { if (FindBar.Visibility == Visibility.Visible) UpdateFind(true); }

    void FindBox_KeyDown(object s, KeyEventArgs e)
    {
        if (e.Key == Key.Enter || e.Key == Key.F3)
        {
            FindStep((Keyboard.Modifiers & ModifierKeys.Shift) != 0 ? -1 : +1);
            e.Handled = true;
        }
        else if (e.Key == Key.Escape) { HideFindBar(); e.Handled = true; }
    }

    void SetCount(string text, bool bad = false)
    {
        FindCount.Text = text;
        FindCount.Foreground = bad ? FindBad : (Brush)FindResource("Muted");
    }

    void UpdateFind(bool jump)
    {
        if (PseudoVisible) FindPseudo(FindBox.Text, jump);
        else { PseudoOverlay.Children.Clear(); FindDisasm(FindBox.Text, jump); }
    }

    void FindStep(int dir)
    {
        string q = FindBox.Text;
        if (string.IsNullOrEmpty(q)) return;
        if (PseudoVisible) StepPseudo(q, dir); else StepDisasm(q, dir);
    }

    static bool FindLineMatch(DisasmLine l, string q)
    {
        var c = StringComparison.OrdinalIgnoreCase;
        return (l.Offset ?? "").Contains(q, c) || (l.Bytes ?? "").Contains(q, c) || (l.Opcode ?? "").Contains(q, c) ||
               (l.Arg ?? "").Contains(q, c) || (l.Operand ?? "").Contains(q, c) || (l.Comment ?? "").Contains(q, c);
    }

    List<int> DisasmMatches(string q)
    {
        var res = new List<int>();
        for (int i = 0; i < _lines.Count; i++) if (FindLineMatch(_lines[i], q)) res.Add(i);
        return res;
    }

    void ShowDisasmMatch(List<int> m, int k)
    {
        int idx = m[k];
        Disasm.SelectedIndex = idx;
        Disasm.ScrollIntoView(_lines[idx]);
        SetCount($"{k + 1} / {m.Count}");
        StatusLeft.Text = $"Found '{FindBox.Text}' at {_lines[idx].Offset}";
    }

    void FindDisasm(string q, bool jump)
    {
        if (string.IsNullOrEmpty(q)) { SetCount(""); return; }
        var m = DisasmMatches(q);
        if (m.Count == 0) { SetCount("No results", true); return; }
        if (!jump) { SetCount($"{m.Count} result(s)"); return; }
        int sel = Math.Max(0, Disasm.SelectedIndex);
        int k = m.FindIndex(i => i >= sel);
        ShowDisasmMatch(m, k < 0 ? 0 : k);
    }

    void StepDisasm(string q, int dir)
    {
        var m = DisasmMatches(q);
        if (m.Count == 0) { SetCount("No results", true); return; }
        int sel = Disasm.SelectedIndex, k;
        if (dir > 0) { k = m.FindIndex(i => i > sel); if (k < 0) k = 0; }
        else { k = m.FindLastIndex(i => i < sel); if (k < 0) k = m.Count - 1; }
        ShowDisasmMatch(m, k);
    }

    void FindPseudo(string q, bool jump)
    {
        PseudoOverlay.Children.Clear();
        _pMatches.Clear();
        _pCur = -1;
        if (string.IsNullOrEmpty(q)) { SetCount(""); return; }

        int p = 0;
        while (_pMatches.Count < 50000)
        {
            int i = _pseudoSrc.IndexOf(q, p, StringComparison.OrdinalIgnoreCase);
            if (i < 0) break;
            _pMatches.Add((i, q.Length));
            p = i + Math.Max(1, q.Length);
        }
        if (_pMatches.Count == 0) { SetCount("No results", true); return; }

        if (jump)
        {
            int k = _pMatches.FindIndex(m => m.Start >= _pLastStart);
            ShowPseudoMatch(k < 0 ? 0 : k);
        }
        else
        {
            SetCount($"{_pMatches.Count} result(s)");
            DrawPseudoHl();
        }
    }

    void StepPseudo(string q, int dir)
    {
        if (_pMatches.Count == 0) { FindPseudo(q, true); return; }
        int k;
        if (dir > 0) { k = _pMatches.FindIndex(m => m.Start > _pLastStart); if (k < 0) k = 0; }
        else { k = _pMatches.FindLastIndex(m => m.Start < _pLastStart); if (k < 0) k = _pMatches.Count - 1; }
        ShowPseudoMatch(k);
    }

    void ShowPseudoMatch(int k)
    {
        _pCur = k;
        _pLastStart = _pMatches[k].Start;
        SetCount($"{k + 1} / {_pMatches.Count}");
        DrawPseudoHl();
        ScrollToMatch(_pMatches[k]);

        try
        {
            var a = PointerAt(_pMatches[k].Start);
            var b = PointerAt(_pMatches[k].Start + _pMatches[k].Len - 1)?.GetPositionAtOffset(1);
            if (a != null && b != null) Pseudo.Selection.Select(a, b);
        }
        catch (Exception) { }
        StatusLeft.Text = $"Found '{FindBox.Text}' at line {LineOf(_pMatches[k].Start)}";
    }

    int LineOf(int off)
    {
        int line = 1;
        for (int i = 0; i < off && i < _pseudoSrc.Length; i++) if (_pseudoSrc[i] == '\n') line++;
        return line;
    }

    TextPointer PointerAt(int off)
    {
        int lo = 0, hi = _runStarts.Count - 1, r = -1;
        while (lo <= hi)
        {
            int mid = (lo + hi) / 2;
            if (_runStarts[mid] <= off) { r = mid; lo = mid + 1; } else hi = mid - 1;
        }
        if (r < 0) return null;
        int k = off - _runStarts[r];
        if (k < 0 || k > _runs[r].Text.Length) return null;
        return _runs[r].ContentStart.GetPositionAtOffset(k, LogicalDirection.Forward);
    }

    Rect? MatchRect(int start, int len)
    {
        var a = PointerAt(start);
        var b = PointerAt(start + len - 1);
        if (a == null || b == null) return null;
        var ra = a.GetCharacterRect(LogicalDirection.Forward);
        var rb = b.GetCharacterRect(LogicalDirection.Forward);
        if (ra.IsEmpty || rb.IsEmpty) return null;
        return new Rect(ra.Left, ra.Top, Math.Max(3, rb.Right - ra.Left), ra.Height);
    }

    void DrawPseudoHl()
    {
        PseudoOverlay.Children.Clear();
        if (_pMatches.Count == 0) return;
        try
        {
            Pseudo.UpdateLayout();
            bool all = _pMatches.Count <= MaxDrawnMatches;
            for (int k = 0; k < _pMatches.Count; k++)
            {
                if (!all && k != _pCur) continue;
                var r = MatchRect(_pMatches[k].Start, _pMatches[k].Len);
                if (r == null) continue;
                var rect = new Rectangle
                {
                    Width = r.Value.Width, Height = r.Value.Height, RadiusX = 2, RadiusY = 2,
                    Fill = k == _pCur ? HlCur : HlAll,
                };
                Canvas.SetLeft(rect, r.Value.Left);
                Canvas.SetTop(rect, r.Value.Top);
                PseudoOverlay.Children.Add(rect);
            }
        }
        catch (Exception) { PseudoOverlay.Children.Clear(); }
    }

    void ScrollToMatch((int Start, int Len) m)
    {
        try
        {
            PseudoScroll.UpdateLayout();
            var r = MatchRect(m.Start, m.Len);
            if (r == null) return;
            Point p = Pseudo.TranslatePoint(new Point(r.Value.Left, r.Value.Top), PseudoScroll);
            if (p.Y < 20 || p.Y > PseudoScroll.ViewportHeight - 40)
                PseudoScroll.ScrollToVerticalOffset(Math.Max(0, PseudoScroll.VerticalOffset + p.Y - PseudoScroll.ViewportHeight / 2));
            if (p.X < 60 || p.X + r.Value.Width > PseudoScroll.ViewportWidth - 40)
                PseudoScroll.ScrollToHorizontalOffset(Math.Max(0, PseudoScroll.HorizontalOffset + p.X - PseudoScroll.ViewportWidth / 3));
        }
        catch (Exception) { }
    }
}
