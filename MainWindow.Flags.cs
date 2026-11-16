using System.Windows;
using System.Windows.Controls;
using System.Windows.Input;
using System.Windows.Media;
using System.Text;
using Opcodex.Pyc;

namespace Opcodex;

public sealed class FlagGroupView
{
    static SolidColorBrush Frozen(string hex)
    {
        var brush = (SolidColorBrush)new BrushConverter().ConvertFromString(hex);
        brush.Freeze();
        return brush;
    }

    static readonly SolidColorBrush InfoColor = Frozen("#569CD6");
    static readonly SolidColorBrush SuspiciousColor = Frozen("#E5A04B");
    static readonly SolidColorBrush MaliciousColor = Frozen("#F14C4C");

    public FlagGroupView(FlagHit hit)
    {
        Hit = hit;
        Label = hit.Label;
        Severity = hit.Severity.ToString();
        Category = hit.Category;
        EvidenceCount = hit.TotalEvidence;
        Description = hit.Description;
    }

    public FlagHit Hit { get; }
    public string Label { get; }
    public string Severity { get; }
    public string Category { get; }
    public int EvidenceCount { get; }
    public string Description { get; }
    public List<FlagRow> Rows { get; } = new();
    public Brush Color => Severity switch
    {
        "Malicious" => MaliciousColor,
        "Suspicious" => SuspiciousColor,
        _ => InfoColor
    };
    public string ToolTipText => $"{Severity} · {Category}\n{Description}";
}

public record FlagRow(FlagGroupView Group, string Kind, string Evidence, string Where, PyCode Code)
{
    public string Preview
    {
        get
        {
            if (string.IsNullOrWhiteSpace(Evidence)) return "";
            var text = string.Join(" ", Evidence.Split((char[])null, StringSplitOptions.RemoveEmptyEntries));
            if (text.StartsWith("…", StringComparison.Ordinal))
            {
                int firstSpace = text.IndexOf(' ');
                if (firstSpace > 0) text = "…" + text.Substring(firstSpace + 1);
            }

            const int maxLength = 36;
            if (text.Length <= maxLength) return text;
            int end = text.LastIndexOf(' ', maxLength - 1);
            if (end < 22) end = maxLength - 1;
            return text.Substring(0, end).TrimEnd() + "…";
        }
    }

    public string FullToolTip => string.IsNullOrEmpty(Where) ? Evidence : $"{Evidence}\n{Where}";
}

public partial class MainWindow
{
    List<FlagHit> _flags = new();

    static string CodeLabel(PyCode code) =>
        code == null ? "" : (string.IsNullOrEmpty(code.QualName) ? code.Name : code.QualName);

    void ApplyFlags(List<FlagHit> hits)
    {
        _flags = hits ?? new List<FlagHit>();

        var groups = new List<FlagGroupView>();
        foreach (var hit in _flags)
        {
            var group = new FlagGroupView(hit);
            foreach (var evidence in hit.Evidence)
                group.Rows.Add(new FlagRow(group, evidence.Kind, evidence.Text, CodeLabel(evidence.Code), evidence.Code));
            groups.Add(group);
        }

        FlagTree.ItemsSource = groups;
        FlagCountText.Text = _flags.Count.ToString();
        bool hasEvidence = groups.Count > 0;
        FlagTree.Visibility = hasEvidence ? Visibility.Visible : Visibility.Collapsed;
        FlagEmptyText.Visibility = hasEvidence ? Visibility.Collapsed : Visibility.Visible;
        FlagEmptyText.Text = _pyc == null
            ? "Open a .pyc file to scan for behavior flags"
            : "No behavior flags detected";

        if (_flags.Count > 0)
            Log($"Flags ({_flags.Count}): " + string.Join(", ", _flags.Select(hit => hit.Label)));
        else
            Log("Flags: none detected.");
    }

    void ShowFlags_Click(object sender, RoutedEventArgs e)
    {
        if (FlagTree.Items.Count == 0) return;
        FlagTree.UpdateLayout();
        if (FlagTree.ItemContainerGenerator.ContainerFromIndex(0) is TreeViewItem first)
        {
            first.IsExpanded = true;
            first.IsSelected = true;
            first.Focus();
            first.BringIntoView();
        }
        else
        {
            FlagTree.Focus();
        }
    }

    static TreeViewItem FlagItemAt(object source, out bool onToggle)
    {
        onToggle = false;
        var element = source as DependencyObject;
        while (element != null)
        {
            if (element is System.Windows.Controls.Primitives.ToggleButton) onToggle = true;
            if (element is TreeViewItem item) return item;
            bool isVisual = element is Visual || element is System.Windows.Media.Media3D.Visual3D;
            element = isVisual ? VisualTreeHelper.GetParent(element) : LogicalTreeHelper.GetParent(element);
        }
        return null;
    }

    void FlagTree_Down(object sender, MouseButtonEventArgs e)
    {
        var item = FlagItemAt(e.OriginalSource, out bool onToggle);
        if (item == null || onToggle || item.DataContext is not FlagGroupView) return;
        item.IsSelected = true;
        item.Focus();
        item.IsExpanded = !item.IsExpanded;
        e.Handled = true;
    }

    void FlagTree_Click(object sender, MouseButtonEventArgs e)
    {
        var item = FlagItemAt(e.OriginalSource, out bool onToggle);
        if (item != null && !onToggle && item.DataContext is FlagRow row)
            GoToFlagRow(row);
    }

    void FlagTree_KeyDown(object sender, KeyEventArgs e)
    {
        if (e.Key == Key.Enter && FlagTree.SelectedItem is FlagRow row)
        {
            GoToFlagRow(row);
            e.Handled = true;
        }
    }

    async void GoToFlagRow(FlagRow row)
    {
        if (row.Code == null || !_nodes.TryGetValue(row.Code, out var node)) return;
        bool pseudoView = PseudoVisible;
        for (var parent = node.Parent as TreeViewItem; parent != null; parent = parent.Parent as TreeViewItem)
            parent.IsExpanded = true;
        _suppressTree = true;
        node.IsSelected = true;
        _suppressTree = false;
        node.BringIntoView();

        if (_cur != row.Code)
            LoadCode(row.Code, refreshPseudo: false);

        if (pseudoView)
        {
            CenterTabs.SelectedItem = PseudoTab;
            if (_pseudoDirty) await BuildPseudoAsync();
            NavigatePseudoToEvidence(row);
            return;
        }

        CenterTabs.SelectedItem = DisasmTab;
        int index = FindEvidenceInstruction(row);
        if (index < 0) index = FindLineIndex(line => line.Insn != null);
        if (index >= 0) Navigate(_lines[index].Insn.Offset);
    }

    int FindEvidenceInstruction(FlagRow row)
    {
        string needle = EvidenceNeedle(row.Evidence);
        if (row.Kind == "name")
        {
            int nameIndex = Array.FindIndex(row.Code.Names,
                name => string.Equals(name, row.Evidence, StringComparison.Ordinal));
            if (nameIndex >= 0)
            {
                int match = FindLineIndex(line => line.Insn?.RefKind == 'n' && line.Insn.RefIndex == nameIndex);
                if (match >= 0) return match;
            }
        }

        foreach (var line in _lines)
        {
            var instruction = line.Insn;
            if (instruction == null) continue;

            if (instruction.RefKind == 'c' && instruction.RefIndex >= 0 && instruction.RefIndex < row.Code.Consts.Count)
            {
                string value = ConstantText(row.Code.Consts[instruction.RefIndex]);
                if (ContainsEvidence(value, needle)) return _lines.IndexOf(line);
            }

            if (!string.IsNullOrEmpty(needle) &&
                instruction.Operand.IndexOf(needle, StringComparison.OrdinalIgnoreCase) >= 0)
                return _lines.IndexOf(line);
        }

        if (row.Kind == "import")
        {
            string importName = ImportName(row.Evidence);
            if (!string.IsNullOrEmpty(importName))
            {
                int match = FindLineIndex(line =>
                    line.Insn?.Name == "IMPORT_NAME" &&
                    line.Insn.Operand.IndexOf(importName, StringComparison.OrdinalIgnoreCase) >= 0);
                if (match >= 0) return match;
            }
        }

        return -1;
    }

    int FindLineIndex(Predicate<DisasmLine> predicate)
    {
        for (int i = 0; i < _lines.Count; i++)
            if (predicate(_lines[i])) return i;
        return -1;
    }

    bool NavigatePseudoToEvidence(FlagRow row)
    {
        foreach (string term in EvidenceSearchTerms(row))
        {
            int start = _pseudoSrc.IndexOf(term, StringComparison.OrdinalIgnoreCase);
            if (start < 0) continue;
            SelectPseudoText(start, term.Length);
            return true;
        }

        if (!string.IsNullOrEmpty(row.Code.Name) && row.Code.Name != "<module>")
        {
            int start = _pseudoSrc.IndexOf(row.Code.Name, StringComparison.Ordinal);
            if (start >= 0)
            {
                SelectPseudoText(start, row.Code.Name.Length);
                return false;
            }
        }

        int firstText = 0;
        while (firstText < _pseudoSrc.Length && char.IsWhiteSpace(_pseudoSrc[firstText])) firstText++;
        if (firstText < _pseudoSrc.Length) SelectPseudoText(firstText, 1);
        return false;
    }

    void SelectPseudoText(int start, int length)
    {
        var begin = PointerAt(start);
        var end = PointerAt(start + length - 1)?.GetPositionAtOffset(1);
        if (begin == null || end == null) return;
        ScrollToMatch((start, length));
        Pseudo.Selection.Select(begin, end);
        Pseudo.Focus();
    }

    static IEnumerable<string> EvidenceSearchTerms(FlagRow row)
    {
        string needle = EvidenceNeedle(row.Evidence);
        if (needle.Length >= 3) yield return needle;

        if (row.Kind == "import")
        {
            string importName = ImportName(row.Evidence);
            if (!string.IsNullOrEmpty(importName) && !string.Equals(importName, needle, StringComparison.Ordinal))
                yield return importName;
        }
        else if (row.Kind == "name" && !string.IsNullOrEmpty(needle))
        {
            yield return needle;
        }
        else
        {
            foreach (string token in needle.Split(new[] { ' ', '\t', '\r', '\n', '.', '/', '\\', '-', ':', ',', ';' },
                         StringSplitOptions.RemoveEmptyEntries).OrderByDescending(token => token.Length))
                if (token.Length >= 4 && !string.Equals(token, needle, StringComparison.Ordinal))
                    yield return token;
        }
    }

    static string EvidenceNeedle(string evidence) =>
        (evidence ?? "").Trim().TrimStart('…').TrimEnd('…').Trim();

    static bool ContainsEvidence(string text, string needle) =>
        !string.IsNullOrEmpty(needle) && text.IndexOf(needle, StringComparison.OrdinalIgnoreCase) >= 0;

    static string ConstantText(PyObj value) => value switch
    {
        PyStr text => text.Value,
        PyBytes bytes => Encoding.Latin1.GetString(bytes.Data),
        _ => value?.Repr() ?? ""
    };

    static string ImportName(string evidence)
    {
        var parts = (evidence ?? "").Split(new[] { ' ', '\t', '\r', '\n' }, StringSplitOptions.RemoveEmptyEntries);
        if (parts.Length > 1 && parts[0] == "from") return parts[1].Trim(',', ';');
        int keyword = Array.FindIndex(parts, part => part == "import");
        if (keyword < 0 || keyword + 1 >= parts.Length) return "";
        string name = parts[keyword + 1].Trim(',', ';');
        return name == "*" ? "" : name;
    }

    void FlagsReport_Click(object sender, RoutedEventArgs e)
    {
        if (_pyc == null)
        {
            Log("Flags: no file loaded.");
            return;
        }

        try
        {
            Clipboard.SetText(FlagScanner.ToText(_pyc, _flags));
            Log("Flags report copied to the clipboard.");
            StatusLeft.Text = "Flags report copied to the clipboard";
        }
        catch (Exception ex)
        {
            Log($"Copy failed: {ex.Message}");
        }
    }
}
