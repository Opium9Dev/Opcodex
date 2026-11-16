using System.Text.RegularExpressions;

namespace Opcodex.Pyc;

public enum PythonTokenKind
{
    Plain,
    Comment,
    StringPrefix,
    String,
    Number,
    Keyword,
    Constant,
    Builtin,
    BuiltinFunction,
    Variable,
    Parameter,
    FunctionName,
    FunctionCall,
    ClassName,
    TypeName,
    Attribute,
    Decorator,
    ImportedName,
    Operator,
    Punctuation,
    Interpolation,
}

public readonly record struct PythonToken(int Start, int Length, PythonTokenKind Kind);

public sealed class PythonSyntaxState
{
    internal string Declaration;
    internal string TripleDelimiter;
    internal string ImportMode;
    internal bool ParameterListPending;
    internal bool InParameterList;
    internal bool ExpectingParameter;
    internal bool ImportAliasPending;
    internal int ParameterNesting;
    internal int ImportParenNesting;
    internal HashSet<string> ImportedIdentifiers = new(StringComparer.Ordinal);
    internal HashSet<string> DefinedClasses = new(StringComparer.Ordinal);
}

public static class PythonSyntaxHighlighter
{
    static readonly Regex TokenPattern = new(
        @"(?<comment>\#[^\n]*)" +
        @"|(?<string>(?i:(?:r|u|b|f|br|rb|fr|rf)?)(?:'''[\s\S]*?'''|\x22{3}[\s\S]*?\x22{3}|'(?!'')(?:\\.|[^'\\\n])*'|""(?!\x22{2})(?:\\.|[^""\\\n])*""))" +
        @"|(?<decorator>@[A-Za-z_]\w*(?:\.[A-Za-z_]\w*)*)" +
        @"|(?<tripleStart>(?i:(?:r|u|b|f|br|rb|fr|rf)?)(?:'''|\x22{3}))" +
        @"|(?<number>(?<![\w.])(?:0[xX][0-9A-Fa-f](?:_?[0-9A-Fa-f])*|0[bB][01](?:_?[01])*|0[oO][0-7](?:_?[0-7])*|(?:\d(?:_?\d)*\.(?:\d(?:_?\d)*)?|\.\d(?:_?\d)*|\d(?:_?\d)*)(?:[eE][+-]?\d(?:_?\d)*)?[jJ]?))(?![\w.])" +
        @"|(?<identifier>[A-Za-z_]\w*)" +
        @"|(?<operator>\*\*=|//=|<<=|>>=|:=|==|!=|<=|>=|->|\+=|-=|\*=|/=|%=|@=|&=|\|=|\^=|[+\-*/%@&|^~<>=])" +
        @"|(?<punctuation>[(){}\[\],.:;])",
        RegexOptions.Compiled);

    static readonly HashSet<string> Keywords = new(StringComparer.Ordinal)
    {
        "False", "None", "True", "and", "as", "assert", "async", "await", "break",
        "case", "class", "continue", "def", "del", "elif", "else", "except", "finally",
        "for", "from", "global", "if", "import", "in", "is", "lambda", "match", "nonlocal",
        "not", "or", "pass", "raise", "return", "try", "while", "with", "yield",
    };

    static readonly HashSet<string> Constants = new(StringComparer.Ordinal)
    {
        "False", "None", "True", "NotImplemented", "Ellipsis", "__debug__",
    };

    static readonly HashSet<string> Builtins = new(StringComparer.Ordinal)
    {
        "__import__", "abs", "aiter", "all", "anext", "any", "ascii", "bin", "bool",
        "breakpoint", "bytearray", "bytes", "callable", "chr", "classmethod", "compile",
        "complex", "delattr", "dict", "dir", "divmod", "enumerate", "eval", "exec",
        "filter", "float", "format", "frozenset", "getattr", "globals", "hasattr", "hash",
        "help", "hex", "id", "input", "int", "isinstance", "issubclass", "iter", "len",
        "list", "locals", "map", "max", "memoryview", "min", "next", "object", "oct",
        "open", "ord", "pow", "print", "property", "range", "repr", "reversed", "round",
        "set", "setattr", "slice", "sorted", "staticmethod", "str", "sum", "super", "tuple",
        "type", "vars", "zip",
    };

    static readonly HashSet<string> BuiltinFunctions = new(StringComparer.Ordinal)
    {
        "__import__", "abs", "aiter", "all", "anext", "any", "ascii", "bin",
        "breakpoint", "callable", "chr", "compile", "delattr", "dir", "divmod",
        "enumerate", "eval", "exec", "filter", "format", "getattr", "globals",
        "hasattr", "hash", "help", "hex", "id", "input", "isinstance", "issubclass",
        "iter", "len", "locals", "map", "max", "min", "next", "oct", "open", "ord",
        "pow", "print", "repr", "reversed", "round", "setattr", "sorted", "sum",
        "vars", "zip",
    };

    static readonly HashSet<string> ExceptionTypes = new(StringComparer.Ordinal)
    {
        "ArithmeticError", "AssertionError", "AttributeError", "BaseException",
        "BaseExceptionGroup", "BlockingIOError", "BrokenPipeError", "BufferError",
        "BytesWarning", "ChildProcessError", "ConnectionAbortedError", "ConnectionError",
        "ConnectionRefusedError", "ConnectionResetError", "DeprecationWarning", "EOFError",
        "EncodingWarning", "Exception", "ExceptionGroup", "FileExistsError",
        "FileNotFoundError", "FloatingPointError", "FutureWarning", "GeneratorExit",
        "ImportError", "ImportWarning", "IndentationError", "IndexError", "InterruptedError",
        "IsADirectoryError", "KeyError", "KeyboardInterrupt", "LookupError", "MemoryError",
        "ModuleNotFoundError", "NameError", "NotADirectoryError", "NotImplementedError",
        "OSError", "OverflowError", "PendingDeprecationWarning", "PermissionError",
        "ProcessLookupError", "RecursionError", "ReferenceError", "ResourceWarning",
        "RuntimeError", "RuntimeWarning", "StopAsyncIteration", "StopIteration",
        "SyntaxError", "SyntaxWarning", "SystemError", "SystemExit", "TabError",
        "TimeoutError", "TypeError", "UnboundLocalError", "UnicodeDecodeError",
        "UnicodeEncodeError", "UnicodeError", "UnicodeTranslateError", "UnicodeWarning",
        "UserWarning", "ValueError", "Warning", "ZeroDivisionError",
    };

    public static IReadOnlyList<PythonToken> TokenizeLine(string line)
        => TokenizeLine(line, new PythonSyntaxState());

    public static IReadOnlyList<PythonToken> TokenizeLine(string line, PythonSyntaxState state)
    {
        ArgumentNullException.ThrowIfNull(line);
        ArgumentNullException.ThrowIfNull(state);
        var tokens = new List<PythonToken>();
        int position = 0;
        if (state.TripleDelimiter != null)
        {
            int closing = line.IndexOf(state.TripleDelimiter, StringComparison.Ordinal);
            if (closing < 0)
            {
                if (line.Length > 0) tokens.Add(new PythonToken(0, line.Length, PythonTokenKind.String));
                return tokens;
            }
            position = closing + state.TripleDelimiter.Length;
            tokens.Add(new PythonToken(0, position, PythonTokenKind.String));
            state.TripleDelimiter = null;
        }
        foreach (Match match in TokenPattern.Matches(line, position))
        {
            if (match.Index > position)
                tokens.Add(new PythonToken(position, match.Index - position, PythonTokenKind.Plain));

            PythonTokenKind kind;
            if (match.Groups["comment"].Success) kind = PythonTokenKind.Comment;
            else if (match.Groups["string"].Success)
            {
                AddStringTokens(line, match.Index, match.Length, tokens);
                position = match.Index + match.Length;
                continue;
            }
            else if (match.Groups["decorator"].Success) kind = PythonTokenKind.Decorator;
            else if (match.Groups["tripleStart"].Success)
            {
                string text = match.Value;
                int singleQuote = text.IndexOf('\'');
                int doubleQuote = text.IndexOf('"');
                int quote = singleQuote < 0 ? doubleQuote
                    : doubleQuote < 0 ? singleQuote
                    : Math.Min(singleQuote, doubleQuote);
                if (quote > 0)
                    tokens.Add(new PythonToken(match.Index, quote, PythonTokenKind.StringPrefix));
                state.TripleDelimiter = new string(text[quote], 3);
                tokens.Add(new PythonToken(match.Index + quote, line.Length - match.Index - quote, PythonTokenKind.String));
                position = line.Length;
                break;
            }
            else if (match.Groups["number"].Success) kind = PythonTokenKind.Number;
            else if (match.Groups["operator"].Success) kind = PythonTokenKind.Operator;
            else if (match.Groups["punctuation"].Success)
            {
                kind = PythonTokenKind.Punctuation;
                if (state.ParameterListPending && match.Value == "(")
                {
                    state.ParameterListPending = false;
                    state.InParameterList = true;
                    state.ParameterNesting = 1;
                    state.ExpectingParameter = true;
                }
                else if (state.InParameterList)
                {
                    if (match.Value is "(" or "[" or "{")
                        state.ParameterNesting++;
                    else if (match.Value is ")" or "]" or "}")
                    {
                        state.ParameterNesting--;
                        if (state.ParameterNesting == 0) state.InParameterList = false;
                    }
                    else if (match.Value == "," && state.ParameterNesting == 1)
                        state.ExpectingParameter = true;
                }
                if (state.ImportMode != null)
                {
                    if (match.Value == "(") state.ImportParenNesting++;
                    else if (match.Value == ")" && state.ImportParenNesting > 0)
                        state.ImportParenNesting--;
                    else if (match.Value == "," && state.ImportMode == "names")
                        state.ImportAliasPending = false;
                    else if (match.Value == ";" && state.ImportParenNesting == 0)
                    {
                        state.ImportMode = null;
                        state.ImportAliasPending = false;
                    }
                }
            }
            else if (match.Groups["identifier"].Success)
            {
                string identifier = match.Value;
                if (state.Declaration != null)
                {
                    kind = state.Declaration == "class" ? PythonTokenKind.ClassName : PythonTokenKind.FunctionName;
                    if (state.Declaration == "class") state.DefinedClasses.Add(identifier);
                    else state.ParameterListPending = true;
                    state.Declaration = null;
                }
                else if (Keywords.Contains(identifier))
                {
                    kind = Constants.Contains(identifier) ? PythonTokenKind.Constant : PythonTokenKind.Keyword;
                    if (identifier == "def") state.Declaration = "function";
                    else if (identifier == "class") state.Declaration = "class";
                    else if (identifier == "from")
                    {
                        state.ImportMode = "module";
                        state.ImportAliasPending = false;
                    }
                    else if (identifier == "import")
                    {
                        state.ImportMode = "names";
                        state.ImportAliasPending = false;
                    }
                    else if (identifier == "as" && state.ImportMode == "names")
                        state.ImportAliasPending = true;
                }
                else if (state.InParameterList && state.ExpectingParameter && state.ParameterNesting == 1)
                {
                    kind = PythonTokenKind.Parameter;
                    state.ExpectingParameter = false;
                }
                else if (state.ImportMode != null)
                {
                    kind = PythonTokenKind.ImportedName;
                    state.ImportedIdentifiers.Add(identifier);
                    state.ImportAliasPending = false;
                }
                else if (state.ImportedIdentifiers.Contains(identifier))
                    kind = PythonTokenKind.ImportedName;
                else if (state.DefinedClasses.Contains(identifier) || ExceptionTypes.Contains(identifier))
                    kind = PythonTokenKind.TypeName;
                else if (PreviousNonWhitespaceIs(line, match.Index, '.') &&
                    NextNonWhitespaceIs(line, match.Index + match.Length, '('))
                    kind = PythonTokenKind.FunctionCall;
                else if (PreviousNonWhitespaceIs(line, match.Index, '.'))
                    kind = PythonTokenKind.Attribute;
                else if (BuiltinFunctions.Contains(identifier))
                    kind = PythonTokenKind.BuiltinFunction;
                else if (Builtins.Contains(identifier))
                    kind = PythonTokenKind.Builtin;
                else if (NextNonWhitespaceIs(line, match.Index + match.Length, '('))
                    kind = PythonTokenKind.FunctionCall;
                else
                    kind = PythonTokenKind.Variable;
            }
            else kind = PythonTokenKind.Plain;

            tokens.Add(new PythonToken(match.Index, match.Length, kind));
            position = match.Index + match.Length;
            if (state.InParameterList && match.Groups["operator"].Success &&
                state.ParameterNesting == 1 && match.Value is "*" or "**")
                state.ExpectingParameter = true;
        }

        if (position < line.Length)
            tokens.Add(new PythonToken(position, line.Length - position, PythonTokenKind.Plain));
        if (state.ImportMode != null && state.ImportParenNesting == 0 &&
            !line.TrimEnd().EndsWith("\\", StringComparison.Ordinal))
        {
            state.ImportMode = null;
            state.ImportAliasPending = false;
        }
        return tokens;
    }

    static bool NextNonWhitespaceIs(string text, int index, char value)
    {
        while (index < text.Length && char.IsWhiteSpace(text[index])) index++;
        return index < text.Length && text[index] == value;
    }

    static bool PreviousNonWhitespaceIs(string text, int index, char value)
    {
        while (index > 0 && char.IsWhiteSpace(text[index - 1])) index--;
        return index > 0 && text[index - 1] == value;
    }

    static bool IsFString(string value)
    {
        int quote = value.IndexOfAny(new[] { '\'', '"' });
        return quote > 0 && value.AsSpan(0, quote).IndexOfAny('f', 'F') >= 0;
    }

    static void AddStringTokens(string line, int start, int length, List<PythonToken> tokens)
    {
        int quote = line.IndexOfAny(new[] { '\'', '"' }, start, length);
        if (quote > start)
            tokens.Add(new PythonToken(start, quote - start, PythonTokenKind.StringPrefix));

        if (IsFString(line.Substring(start, length)))
            AddFStringTokens(line, quote, start + length - quote, tokens);
        else
            tokens.Add(new PythonToken(quote, start + length - quote, PythonTokenKind.String));
    }

    static void AddFStringTokens(string line, int start, int length, List<PythonToken> tokens)
    {
        int openingQuote = line.IndexOfAny(new[] { '\'', '"' }, start, length);
        char quote = line[openingQuote];
        int delimiterLength = openingQuote + 2 < start + length &&
            line[openingQuote + 1] == quote && line[openingQuote + 2] == quote ? 3 : 1;
        int contentStart = openingQuote + delimiterLength;
        int contentEnd = start + length - delimiterLength;
        int textStart = start;
        for (int index = contentStart; index < contentEnd;)
        {
            if (line[index] == '{' && index + 1 < contentEnd && line[index + 1] == '{' ||
                line[index] == '}' && index + 1 < contentEnd && line[index + 1] == '}')
            {
                index += 2;
                continue;
            }
            if (line[index] != '{')
            {
                index++;
                continue;
            }

            int closing = FindFStringClosingBrace(line, index, contentEnd);
            if (closing < 0)
            {
                tokens.Add(new PythonToken(textStart, start + length - textStart, PythonTokenKind.String));
                return;
            }
            if (index > textStart)
                tokens.Add(new PythonToken(textStart, index - textStart, PythonTokenKind.String));
            tokens.Add(new PythonToken(index, 1, PythonTokenKind.Interpolation));

            int expressionStart = index + 1;
            int expressionEnd = FindFStringExpressionEnd(line, expressionStart, closing);
            string expression = line.Substring(expressionStart, expressionEnd - expressionStart);
            foreach (PythonToken token in TokenizeLine(expression))
                tokens.Add(token with { Start = token.Start + expressionStart });
            if (expressionEnd < closing)
                tokens.Add(new PythonToken(expressionEnd, closing - expressionEnd, PythonTokenKind.String));
            tokens.Add(new PythonToken(closing, 1, PythonTokenKind.Interpolation));
            index = closing + 1;
            textStart = index;
        }
        if (textStart < start + length)
            tokens.Add(new PythonToken(textStart, start + length - textStart, PythonTokenKind.String));
    }

    static int FindFStringClosingBrace(string text, int opening, int limit)
    {
        int depth = 1;
        char quote = '\0';
        for (int index = opening + 1; index < limit; index++)
        {
            char current = text[index];
            if (quote != '\0')
            {
                if (current == '\\') { index++; continue; }
                if (current == quote) quote = '\0';
                continue;
            }
            if (current is '\'' or '"') { quote = current; continue; }
            if (current == '{') depth++;
            else if (current == '}' && --depth == 0) return index;
        }
        return -1;
    }

    static int FindFStringExpressionEnd(string text, int start, int closing)
    {
        int nesting = 0;
        char quote = '\0';
        for (int index = start; index < closing; index++)
        {
            char current = text[index];
            if (quote != '\0')
            {
                if (current == '\\') { index++; continue; }
                if (current == quote) quote = '\0';
                continue;
            }
            if (current is '\'' or '"') { quote = current; continue; }
            if (current is '(' or '[' or '{') nesting++;
            else if (current is ')' or ']' or '}') nesting--;
            else if (nesting == 0 && (current == ':' || current == '!' &&
                     (index + 1 >= closing || text[index + 1] != '=')))
                return index;
        }
        return closing;
    }
}
