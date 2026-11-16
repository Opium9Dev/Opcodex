namespace Opcodex.Pyc;

public static class StackExprPrinter
{
    public static bool TryPrintSource(StackExpr expression, out string text)
    {
        text = null;
        if (!IsSourceExpression(expression)) return false;
        text = Render(expression, 0, null, false);
        return true;
    }

    internal static string FormatDebug(StackExpr expression)
    {
        string S(StackExpr e) => e?.ToString() ?? "<null>";
        switch (expression.Kind)
        {
            case StackExprKind.Name: return expression.Scope == "cell" ? $"<cell {expression.Text}>" : expression.Text;
            case StackExprKind.Constant: return expression.Constant?.Repr() ?? "<NULL>";
            case StackExprKind.Marker: return $"<{expression.Text}>";
            case StackExprKind.Attribute: return $"{S(expression.Items.ElementAtOrDefault(0))}.{expression.Text}";
            case StackExprKind.Subscript: return $"{S(expression.Items.ElementAtOrDefault(0))}[{S(expression.Items.ElementAtOrDefault(1))}]";
            case StackExprKind.Slice: return string.Join(":", expression.Items.Select(S));
            case StackExprKind.Call:
                var args = expression.Items.Skip(1).Select(S).Concat(expression.Keywords.Select(k =>
                    k.Name == null ? "**" + S(k.Value) : k.Name + "=" + S(k.Value)));
                return $"{S(expression.Items.ElementAtOrDefault(0))}({string.Join(", ", args)})";
            case StackExprKind.Binary:
            case StackExprKind.Compare:
                return $"({S(expression.Items.ElementAtOrDefault(0))} {expression.Text} {S(expression.Items.ElementAtOrDefault(1))})";
            case StackExprKind.Unary: return $"({expression.Text}{S(expression.Items.ElementAtOrDefault(0))})";
            case StackExprKind.Tuple: return expression.Items.Count == 1
                ? $"({S(expression.Items[0])},)"
                : $"({string.Join(", ", expression.Items.Select(S))})";
            case StackExprKind.List: return $"[{string.Join(", ", expression.Items.Select(S))}]";
            case StackExprKind.Set: return expression.Items.Count == 0
                ? "set()"
                : $"{{{string.Join(", ", expression.Items.Select(S))}}}";
            case StackExprKind.Dictionary:
                return $"{{{string.Join(", ", expression.Items.Select((v, i) =>
                    (i & 1) == 0 ? null
                    : expression.Items[i - 1].Kind == StackExprKind.Constant && expression.Items[i - 1].Constant == null
                        ? "**" + S(v)
                        : $"{S(expression.Items[i - 1])}: {S(v)}").Where(x => x != null))}}}";
            case StackExprKind.Starred: return "*" + S(expression.Items.ElementAtOrDefault(0));
            case StackExprKind.Function: return $"<function {expression.Text ?? "?"}>";
            case StackExprKind.Formatted:
                return "{" + S(expression.Items.ElementAtOrDefault(0)) + expression.Text +
                    (expression.Items.Count > 1 ? ":" + S(expression.Items[1]) : "") + "}";
            case StackExprKind.FString: return "f<" + string.Concat(expression.Items.Select(S)) + ">";
            case StackExprKind.Unpack:
                return $"<unpack {S(expression.Items.ElementAtOrDefault(0))}[{expression.Index}/{expression.Count}{(expression.StarIndex == expression.Index ? "*" : "")}]>";
            case StackExprKind.Import: return $"<import {expression.Text}>";
            case StackExprKind.ImportFrom:
                var module = expression.Items.ElementAtOrDefault(0);
                string moduleName = module?.Kind == StackExprKind.Import ? module.Text : S(module);
                return $"<from {moduleName} import {expression.Text}>";
            case StackExprKind.Yield: return $"(yield {S(expression.Items.ElementAtOrDefault(0))})";
            case StackExprKind.YieldFrom: return $"(yield from {S(expression.Items.ElementAtOrDefault(0))})";
            case StackExprKind.Opaque:
                return $"<{expression.Text}{(expression.Items.Count == 0 ? "" : " " + string.Join(", ", expression.Items.Select(S)))}>";
            case StackExprKind.Phi: return $"<phi {expression.Text}>";
            case StackExprKind.HandlerSlot: return $"<{expression.Text}>";
            default: return "<?>";
        }
    }

    static bool IsSourceExpression(StackExpr expression)
    {
        if (expression == null) return false;
        switch (expression.Kind)
        {
            case StackExprKind.Name:
                return !string.IsNullOrWhiteSpace(expression.Text) && !expression.Text.StartsWith("<", StringComparison.Ordinal);
            case StackExprKind.Constant:
                return expression.Constant != null && expression.Constant is not PyCode;
            case StackExprKind.Attribute:
                return expression.Items.Count == 1 && IsIdentifier(expression.Text) && AllItems(expression);
            case StackExprKind.Subscript:
            case StackExprKind.Binary:
            case StackExprKind.Compare:
                return expression.Items.Count == 2 && AllItems(expression);
            case StackExprKind.Unary:
                return expression.Items.Count == 1 && AllItems(expression);
            case StackExprKind.Tuple:
            case StackExprKind.List:
            case StackExprKind.Set:
                return AllItems(expression);
            case StackExprKind.Starred:
            case StackExprKind.Yield:
                return expression.Items.Count == 1 && AllItems(expression);
            case StackExprKind.YieldFrom:
                return expression.Items.Count >= 1 && AllItems(expression);
            case StackExprKind.Slice:
                return expression.Items.Count is 2 or 3 && AllItems(expression);
            case StackExprKind.Call:
                return expression.Items.Count > 0 && AllItems(expression) &&
                    expression.Keywords.All(k => k.Name == null || IsIdentifier(k.Name)) &&
                    expression.Keywords.All(k => IsSourceExpression(k.Value));
            case StackExprKind.Dictionary:
                return expression.Items.Count % 2 == 0 &&
                    Enumerable.Range(0, expression.Items.Count / 2).All(i =>
                        (expression.Items[i * 2].Kind == StackExprKind.Constant && expression.Items[i * 2].Constant == null ||
                         IsSourceExpression(expression.Items[i * 2])) &&
                        IsSourceExpression(expression.Items[i * 2 + 1]));
            case StackExprKind.Formatted:
                return expression.Items.Count is 1 or 2 && AllItems(expression);
            case StackExprKind.FString:
                return false;
            default:
                return false;
        }
    }

    static bool AllItems(StackExpr expression) => expression.Items.All(IsSourceExpression);

    static bool IsIdentifier(string text) =>
        !string.IsNullOrEmpty(text) &&
        (char.IsLetter(text[0]) || text[0] == '_') &&
        text.Skip(1).All(c => char.IsLetterOrDigit(c) || c == '_');

    static string Render(StackExpr expression, int parentPrecedence, string parentOperator, bool rightChild)
    {
        int precedence = Precedence(expression);
        string text;
        switch (expression.Kind)
        {
            case StackExprKind.Name:
                text = expression.Text;
                break;
            case StackExprKind.Constant:
                text = expression.Constant.Repr();
                break;
            case StackExprKind.Attribute:
                text = Render(expression.Items[0], 100, null, false) + "." + expression.Text;
                break;
            case StackExprKind.Subscript:
                text = Render(expression.Items[0], 100, null, false) +
                    "[" + Render(expression.Items[1], 0, null, false) + "]";
                break;
            case StackExprKind.Slice:
                text = string.Join(":", expression.Items.Select(item =>
                    item.Kind == StackExprKind.Constant && item.Constant is PyNone ? "" : Render(item, 0, null, false)));
                break;
            case StackExprKind.Call:
                var args = expression.Items.Skip(1).Select(item => Render(item, 0, null, false)).ToList();
                args.AddRange(expression.Keywords.Select(keyword =>
                    keyword.Name == null
                        ? "**" + Render(keyword.Value, 0, null, false)
                        : keyword.Name + "=" + Render(keyword.Value, 0, null, false)));
                text = Render(expression.Items[0], 100, null, false) + "(" + string.Join(", ", args) + ")";
                break;
            case StackExprKind.Binary:
                text = Render(expression.Items[0], precedence, expression.Text, false) + " " + expression.Text + " " +
                    Render(expression.Items[1], precedence, expression.Text, true);
                break;
            case StackExprKind.Unary:
                text = expression.Text + Render(expression.Items[0], precedence, expression.Text, true);
                break;
            case StackExprKind.Compare:
                text = Render(expression.Items[0], precedence, expression.Text, false) + " " + expression.Text + " " +
                    Render(expression.Items[1], precedence, expression.Text, true);
                break;
            case StackExprKind.Tuple:
                text = "(" + string.Join(", ", expression.Items.Select(item => Render(item, 0, null, false))) +
                    (expression.Items.Count == 1 ? "," : "") + ")";
                break;
            case StackExprKind.List:
                text = "[" + string.Join(", ", expression.Items.Select(item => Render(item, 0, null, false))) + "]";
                break;
            case StackExprKind.Set:
                text = expression.Items.Count == 0
                    ? "set()"
                    : "{" + string.Join(", ", expression.Items.Select(item => Render(item, 0, null, false))) + "}";
                break;
            case StackExprKind.Dictionary:
                var pairs = new List<string>();
                for (int i = 0; i < expression.Items.Count; i += 2)
                    pairs.Add(expression.Items[i].Kind == StackExprKind.Constant && expression.Items[i].Constant == null
                        ? "**" + Render(expression.Items[i + 1], 0, null, false)
                        : Render(expression.Items[i], 0, null, false) + ": " +
                            Render(expression.Items[i + 1], 0, null, false));
                text = "{" + string.Join(", ", pairs) + "}";
                break;
            case StackExprKind.Starred:
                text = "*" + Render(expression.Items[0], precedence, null, true);
                break;
            case StackExprKind.Formatted:
                text = "{" + Render(expression.Items[0], 0, null, false) + expression.Text +
                    (expression.Items.Count > 1 ? ":" + Render(expression.Items[1], 0, null, false) : "") + "}";
                break;
            case StackExprKind.FString:
                text = "f\"" + string.Concat(expression.Items.Select(item => item.Kind == StackExprKind.Constant &&
                    item.Constant is PyStr literal ? literal.Value.Replace("{", "{{").Replace("}", "}}") :
                    "{" + Render(item, 0, null, false) + "}")) + "\"";
                break;
            case StackExprKind.Yield:
                text = "yield " + Render(expression.Items[0], 0, null, false);
                break;
            case StackExprKind.YieldFrom:
                text = "yield from " + Render(expression.Items[0], 0, null, false);
                break;
            default:
                throw new InvalidOperationException($"{expression.Kind} is not a source expression.");
        }

        if (precedence < parentPrecedence ||
            (precedence == parentPrecedence && NeedsEqualPrecedenceParens(expression, parentOperator, rightChild)))
            return "(" + text + ")";
        return text;
    }

    static bool NeedsEqualPrecedenceParens(StackExpr expression, string parentOperator, bool rightChild)
    {
        if (expression.Kind == StackExprKind.Compare) return true;
        if (parentOperator == "**") return !rightChild;
        return rightChild && expression.Kind == StackExprKind.Binary;
    }

    static int Precedence(StackExpr expression)
    {
        if (expression.Kind is StackExprKind.Name or StackExprKind.Constant or StackExprKind.Attribute or
            StackExprKind.Subscript or StackExprKind.Call or StackExprKind.Tuple or StackExprKind.List or
            StackExprKind.Set or StackExprKind.Dictionary or StackExprKind.Formatted or StackExprKind.FString)
            return 100;
        if (expression.Kind == StackExprKind.Binary)
            return expression.Text switch
            {
                "**" => 80,
                "*" or "/" or "//" or "%" or "@" => 70,
                "+" or "-" => 60,
                "<<" or ">>" => 55,
                "&" => 50,
                "^" => 45,
                "|" => 40,
                _ => 60,
            };
        if (expression.Kind == StackExprKind.Compare) return 30;
        if (expression.Kind == StackExprKind.Unary) return expression.Text.Trim() == "not" ? 20 : 75;
        if (expression.Kind == StackExprKind.Yield || expression.Kind == StackExprKind.YieldFrom) return 10;
        return 0;
    }
}
