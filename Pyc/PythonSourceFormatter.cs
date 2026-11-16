using System.IO;
using System.Text;

namespace Opcodex.Pyc;

public static class PythonSourceFormatter
{
    const int MaxDisplayLineLength = 1024;
    const int MaxDisplaySourceLength = 250_000;
    const int MaxLiteralPreviewLength = 256;

    public static string LimitForDisplay(string source)
    {
        ArgumentNullException.ThrowIfNull(source);
        if (source.Length <= MaxDisplaySourceLength)
        {
            int lineStart = 0;
            bool needsTruncation = false;
            for (int index = 0; index <= source.Length; index++)
            {
                if (index != source.Length && source[index] != '\n') continue;
                if (index - lineStart > MaxDisplayLineLength)
                {
                    needsTruncation = true;
                    break;
                }
                lineStart = index + 1;
            }
            if (!needsTruncation) return source;
        }

        var result = new StringBuilder(Math.Min(source.Length, MaxDisplaySourceLength));
        using var reader = new StringReader(source);
        string line;
        while ((line = reader.ReadLine()) != null)
        {
            if (line.Length > MaxDisplayLineLength)
                line = TruncateDisplayLine(line);

            int separatorLength = result.Length == 0 ? 0 : 1;
            if (result.Length + separatorLength + line.Length > MaxDisplaySourceLength)
            {
                const string limitMarker = "# [pseudo-source display limit reached]";
                int markerSeparatorLength = result.Length == 0 ? 0 : 1;
                result.Length = Math.Min(result.Length,
                    MaxDisplaySourceLength - markerSeparatorLength - limitMarker.Length);
                if (markerSeparatorLength > 0) result.Append('\n');
                result.Append(limitMarker);
                break;
            }

            if (separatorLength > 0) result.Append('\n');
            result.Append(line);
        }
        return result.ToString();
    }

    static string TruncateDisplayLine(string line)
    {
        int searchLimit = Math.Min(line.Length, 256);
        for (int index = 0; index < searchLimit; index++)
        {
            char quote = line[index];
            if (quote is not ('\'' or '"')) continue;
            int delimiterLength = index + 2 < line.Length &&
                line[index + 1] == quote && line[index + 2] == quote ? 3 : 1;
            string delimiter = new(quote, delimiterLength);
            int closingDelimiter = line.LastIndexOf(delimiter, StringComparison.Ordinal);
            int contentStart = index + delimiterLength;
            bool hasClosingDelimiter = closingDelimiter >= contentStart;
            int contentEnd = hasClosingDelimiter ? closingDelimiter : line.Length;
            if (contentEnd - contentStart <= MaxLiteralPreviewLength) continue;
            int previewLength = Math.Min(MaxLiteralPreviewLength, contentEnd - contentStart);
            int omitted = contentEnd - contentStart - previewLength;
            string preview = line.Substring(contentStart, previewLength);
            string suffix = hasClosingDelimiter &&
                line.Length - closingDelimiter - delimiterLength <= 256
                ? line.Substring(closingDelimiter + delimiterLength)
                : "";
            return line.Substring(0, index) + delimiter +
                preview + $"... <value truncated: {omitted:N0} characters>" + delimiter + suffix;
        }

        int indentation = line.Length - line.TrimStart(' ', '\t').Length;
        return line.Substring(0, indentation) +
            $"# [long line omitted: {line.Length - indentation:N0} characters]";
    }

    public static string Format(string source)
    {
        ArgumentNullException.ThrowIfNull(source);
        var formatted = new List<string>();
        var syntaxState = new PythonSyntaxState();

        foreach (string line in source.Replace("\r", "").Split('\n'))
        {
            bool insideTripleQuotedString = syntaxState.TripleDelimiter != null;
            PythonSyntaxHighlighter.TokenizeLine(line, syntaxState);
            if (string.IsNullOrWhiteSpace(line) || insideTripleQuotedString)
            {
                formatted.Add(line);
                continue;
            }

            int indentation = line.Length - line.TrimStart(' ', '\t').Length;
            string trimmed = line.TrimStart();
            bool isFunction = trimmed.StartsWith("def ", StringComparison.Ordinal) ||
                trimmed.StartsWith("async def ", StringComparison.Ordinal);
            bool isClass = trimmed.StartsWith("class ", StringComparison.Ordinal);
            int previousIndentation = LastNonBlankIndent(formatted);
            int requiredBlankLines = indentation == 0 && (isFunction || isClass) &&
                previousIndentation >= 0
                ? 1
                : isFunction && previousIndentation == indentation
                    ? 1
                    : 0;

            if (requiredBlankLines > 0)
            {
                int groupStart = formatted.Count;
                while (groupStart > 0)
                {
                    string previous = formatted[groupStart - 1];
                    if (Indentation(previous) != indentation ||
                        !previous.TrimStart().StartsWith("@", StringComparison.Ordinal))
                        break;
                    groupStart--;
                }

                int existingBlankLines = 0;
                for (int index = groupStart - 1; index >= 0 &&
                     string.IsNullOrWhiteSpace(formatted[index]); index--)
                    existingBlankLines++;
                for (int count = existingBlankLines; count < requiredBlankLines; count++)
                    formatted.Insert(groupStart, "");
            }

            formatted.Add(line);
        }

        return string.Join("\n", formatted);
    }

    static int LastNonBlankIndent(List<string> lines)
    {
        for (int index = lines.Count - 1; index >= 0; index--)
            if (!string.IsNullOrWhiteSpace(lines[index]))
                return Indentation(lines[index]);
        return -1;
    }

    static int Indentation(string line) => line.Length - line.TrimStart(' ', '\t').Length;
}
