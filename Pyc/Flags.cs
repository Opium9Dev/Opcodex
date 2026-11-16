using System.IO;
using System.IO.Compression;
using System.Text;
using System.Text.RegularExpressions;

namespace Opcodex.Pyc;

public enum FlagSeverity { Info = 0, Suspicious = 1, Malicious = 2 }

/// <summary>An import found in a code object (populated by MainWindow.ComputeImports).</summary>
public sealed record ImportRec(string Line, string Module, string[] From, PyCode Code);

public sealed class FlagEvidence
{
    public string Kind = "";      // import | name | string | bytes | decoded | blob | rule
    public string Text = "";
    public PyCode Code;
    public object Src;            // Source item identity for deduplication
}

public sealed class FlagHit
{
    public string Id = "", Label = "", Category = "", Description = "";
    public FlagSeverity Severity;
    public List<FlagEvidence> Evidence = new();
    public int TotalEvidence;
    public int Confidence;        // 0-100: how sure the rule is, given corroboration and context
    public bool Boosted;          // severity raised because corroborating signals were also found
    public bool Scattered;        // signals found only in different code objects (Malicious lowered to Suspicious)
    public bool IsCorrelation;    // produced by a correlation chain, not by a single rule
}

public sealed class FlagVerdict
{
    public int Score;             // 0-100
    public string Level = "";     // No significant indicators | Low suspicion | Suspicious | Likely malicious
    public string Summary = "";
}

/// <summary>
/// Static behavior detection for a .pyc using imports, names (co_names), string/byte constants,
/// and decoded content (base64, hex, reversed text, zlib/gzip layers, up to 3 levels deep).
///
/// A rule is a list of AND groups; each group is a list of OR signals. On top of that:
///   Boost(sev, groups)  - extra groups that, when ALSO present, raise the severity (corroboration).
///   Min(n)              - the first group needs at least n distinct matches (e.g. lists of VM artifacts).
///   Near()              - signals should live in the same code object; if scattered, Malicious is lowered
///                         to Suspicious (a hit is never dropped, only downgraded).
/// After the rules, correlation chains combine hits (theft + exfiltration, loader + obfuscation, ...).
/// </summary>
public static class FlagScanner
{
    const int MaxStringLen = 65536;
    const int MaxEvidence = 50;
    const int MaxCollect = 500;
    const int MaxDecoded = 2000;
    const int MaxBlobs = 200;
    const int MaxInflate = 4 * 1024 * 1024;
    const string MarshalMarker = "[marshal-code-object]";

    // Model

    sealed class Item
    {
        public string Text = "", Lower = "", Kind = "";
        public string[] Keys;
        public PyCode Code;
    }

    sealed class Sig
    {
        public char K;                                  // M import, N name, S substring, X regex, E high-entropy blob
        public string[] Subs = Array.Empty<string>();
        public Regex Rx;
    }

    sealed class Rule
    {
        public string Id = "", Label = "", Category = "", Desc = "";
        public FlagSeverity Sev;
        public Sig[][] Groups = Array.Empty<Sig[]>();
        public Sig[][] BoostGroups;
        public FlagSeverity BoostSev;
        public int MinEv = 1;
        public bool IsNear;
        public Rule Boost(FlagSeverity s, params Sig[][] g) { BoostSev = s; BoostGroups = g; return this; }
        public Rule Min(int n) { MinEv = n; return this; }
        public Rule Near() { IsNear = true; return this; }
    }

    sealed class EvalResult
    {
        public List<FlagEvidence> Ev = new();
        public bool Boosted, Scattered;
    }

    sealed class MetaGroup
    {
        public string[] Ids = Array.Empty<string>();
        public int Min = 1;
        public FlagSeverity MinSev = FlagSeverity.Info;
    }

    sealed class Meta
    {
        public string Id = "", Label = "", Desc = "";
        public FlagSeverity Sev, UpSev;
        public MetaGroup[] Req = Array.Empty<MetaGroup>();
        public MetaGroup[] UpReq;
        public Meta Up(FlagSeverity s, params MetaGroup[] g) { UpSev = s; UpReq = g; return this; }
    }

    sealed class Corpus
    {
        public readonly List<Item> Modules = new();
        public readonly List<Item> Strings = new();
        public readonly List<Item> Blobs = new();
        public readonly Dictionary<string, List<Item>> Names = new(StringComparer.OrdinalIgnoreCase);
        readonly HashSet<(string, PyCode)> _nameSeen = new();
        int _decoded;

        public void AddImport(ImportRec r)
        {
            var keys = new List<string>();
            string m = (r.Module ?? "").ToLowerInvariant();
            if (m.Length > 0 && m != "?") keys.Add(m);
            if (r.From != null)
                foreach (var f in r.From)
                    if (!string.IsNullOrEmpty(f)) keys.Add((m.Length > 0 && m != "?" ? m + "." : "") + f.ToLowerInvariant());
            if (keys.Count == 0) return;
            Modules.Add(new Item { Text = r.Line ?? m, Kind = "import", Keys = keys.ToArray(), Code = r.Code });
        }

        public void AddName(string n, PyCode c)
        {
            if (string.IsNullOrEmpty(n) || n[0] == '<') return;
            if (!_nameSeen.Add((n, c))) return;
            if (!Names.TryGetValue(n, out var list)) Names[n] = list = new List<Item>();
            list.Add(new Item { Text = n, Kind = "name", Code = c });
        }

        void Add(string text, string kind, PyCode c) =>
            Strings.Add(new Item { Text = text, Lower = text.ToLowerInvariant(), Kind = kind, Code = c });

        public void AddString(string text, string kind, PyCode c, HashSet<string> seen)
        {
            if (text == null || text.Length < 3) return;
            if (text.Length > MaxStringLen) text = text.Substring(0, MaxStringLen);
            if (!seen.Add(text)) return;
            Add(text, kind, c);
            Expand(text, c, seen, 0);
        }

        public void AddBytes(byte[] data, PyCode c, HashSet<string> seen)
        {
            if (data == null || data.Length < 3) return;
            AddString(Encoding.Latin1.GetString(data, 0, Math.Min(data.Length, MaxStringLen)), "bytes", c, seen);
            if (data.Length < 8 || _decoded >= MaxDecoded) return;

            // Raw marshalled code object stored as a constant.
            if (IsMarshalCode(data) && seen.Add(MarshalMarker + c?.GetHashCode()))
            {
                _decoded++;
                Add(MarshalMarker, "decoded", c);
            }

            // zlib/gzip-compressed constant: look inside it.
            var inf = TryInflate(data);
            if (inf != null)
            {
                var t = Interpret(inf, 1);
                if (t != null && seen.Add(t))
                {
                    _decoded++;
                    Add(t, "decoded", c);
                    Expand(t, c, seen, 1);
                }
            }

            // High-entropy blob (encrypted or compressed payload).
            if (data.Length >= 1024 && Blobs.Count < MaxBlobs && !LooksLikeMedia(data))
            {
                int n = Math.Min(data.Length, MaxStringLen);
                double h = Entropy(data, n);
                if (h >= 7.2)
                    Blobs.Add(new Item { Text = $"{data.Length} bytes, entropy {h:0.00}", Kind = "blob", Code = c });
            }
        }

        // Decode layers (base64 -> zlib -> text, hex, reversed strings...) so hidden URLs, tokens and PE files are visible.
        void Expand(string text, PyCode c, HashSet<string> seen, int depth)
        {
            if (depth >= 3 || _decoded >= MaxDecoded) return;
            foreach (var d in Decoders(text))
            {
                if (_decoded >= MaxDecoded) return;
                if (!seen.Add(d)) continue;
                _decoded++;
                Add(d, "decoded", c);
                if (d != MarshalMarker) Expand(d, c, seen, depth + 1);
            }
        }
    }

    // Rule definitions

    // Signatures are stored base64-encoded so the scanner's own binary/source does not trip
    // string-based detectors. Decoded once at startup.
    static string D(string b64) => Encoding.UTF8.GetString(Convert.FromBase64String(b64));

    static readonly FlagSeverity Inf = FlagSeverity.Info, Sus = FlagSeverity.Suspicious, Mal = FlagSeverity.Malicious;

    static string[] Low(string[] a) => a.Select(x => x.ToLowerInvariant()).ToArray();
    static Sig M(params string[] a) => new Sig { K = 'M', Subs = Low(a) };
    static Sig N(params string[] a) => new Sig { K = 'N', Subs = a };
    static Sig S(params string[] a) => new Sig { K = 'S', Subs = Low(a) };
    static Sig E() => new Sig { K = 'E' };
    static Sig X(string rx) => new Sig
    {
        K = 'X',
        Rx = new Regex(rx, RegexOptions.CultureInvariant | RegexOptions.Compiled, TimeSpan.FromMilliseconds(300)),
    };
    static Sig[] G(params Sig[] s) => s;
    static Rule R(string id, string label, string cat, FlagSeverity sev, string desc, params Sig[][] groups) =>
        new Rule { Id = id, Label = label, Category = cat, Sev = sev, Desc = desc, Groups = groups };

    // Patterns are declared before Rules/Metas so static initialization order is respected.
    static readonly string RxBase64 = D("KD86W0EtWmEtejAtOSsvXXs0fSl7MzAsfSg/OltBLVphLXowLTkrL117Mn09PXxbQS1aYS16MC05Ky9dezN9PSk/");
    static readonly string RxDiscordWebhook = D("KD9pKWh0dHBzPzovLyg/OnB0YlwufGNhbmFyeVwuKT9kaXNjb3JkKD86YXBwKT9cLmNvbS9hcGkvKD86dlxkKy8pP3dlYmhvb2tzL1xkKy9bXHdcLV0r");
    static readonly string RxDiscordToken = D("XGJbTU5PXVtBLVphLXpcZF9cLV17MjMsMjV9XC5bQS1aYS16XGRfXC1dezZ9XC5bQS1aYS16XGRfXC1dezI3LDM4fVxi");
    static readonly string RxDiscordMfa = D("XGJtZmFcLltBLVphLXpcZF9cLV17ODR9XGI=");
    static readonly string RxTelegramToken = D("XGJcZHs4LDEwfTpbQS1aYS16MC05X1wtXXszNX1cYg==");
    static readonly string RxRunAs = D("KD9pKSg/PCFbQS1aYS16XSlydW5hcyg/IVtBLVphLXpdKQ==");
    // Require complete headers at the start of a constant; the marker string alone is also used to detect ELF files.
    static readonly string RxPeHeader = D("KD9zKVxBTVouezAsMjU2fT9UaGlzIHByb2dyYW0gKD86Y2Fubm90fG11c3QpIGJlIHJ1biAoPzppbnx1bmRlcikgKD86RE9TfFdpbjMyKQ==");
    static readonly string RxElfHeader = D("XEFceDdmRUxGW1x4MDFceDAyXVtceDAxXHgwMl1ceDAx");
    static readonly string RxArchiveHeader = D("XEEoPzpQS1x4MDNceDA0fFJhciFceDFhXHgwN3w3elx4YmNceGFmXHgyN1x4MWMp");
    // URL whose host is a public raw IPv4 address (private/loopback ranges excluded).
    static readonly string RxRawIpUrl = D("KD9pKVxiaHR0cHM/Oi8vKD8hKD86MTI3XC58MTBcLnwxOTJcLjE2OFwufDBcLjBcLjBcLjB8MTY5XC4yNTRcLnwxNzJcLig/OjFbNi05XXwyXGR8M1swMV0pXC4pKSg/OjI1WzAtNV18MlswLTRdXGR8MT9cZD9cZCkoPzpcLig/OjI1WzAtNV18MlswLTRdXGR8MT9cZD9cZCkpezN9XGI=");
    // Cryptocurrency addresses (ETH, bech32 BTC, Monero, legacy BTC with mixed letters+digits to avoid random identifiers).
    static readonly string RxCryptoAddr = D("XGIoPzoweFthLWZBLUYwLTldezQwfXxiYzFbYS16MC05XXsyNSw2Mn18NFswLTlBQl1bMS05QS1ISi1OUC1aYS1rbS16XXs5M318WzEzXSg/PVthLWttLXpBLUhKLU5QLVoxLTldKlxkKSg/PVthLWttLXpBLUhKLU5QLVoxLTldKlthLXpdKSg/PVthLWttLXpBLUhKLU5QLVoxLTldKltBLVpdKVthLWttLXpBLUhKLU5QLVoxLTldezI1LDM0fSlcYg==");
    static readonly string RxRansomText = D("KD9pKSg/OlxicmFuc29tfHlvdXIgKD86ZmlsZXN8ZGF0YXxkb2N1bWVudHN8bmV0d29yaylbXi5cclxuXXswLDQwfSg/OmVuY3J5cHRlZHxsb2NrZWQpfGZpbGVzPyAoPzpoYXN8aGF2ZXxhcmV8d2VyZXxiZWVuKVteLlxyXG5dezAsMjB9KD86ZW5jcnlwdGVkfGxvY2tlZCl8KD86cGF5fHNlbmQpW14uXHJcbl17MCw0MH0oPzpiaXRjb2lufGJ0Y3xtb25lcm98eG1yKXxob3dbXyBddG9bXyBdKD86ZGVjcnlwdHxyZWNvdmVyfHJlc3RvcmUpfHJlY292ZXIoPzp5KT9bXyBdeW91cltfIF1maWxlc3xkZWNyeXB0W18gXWluc3RydWN0aW9ucyk=");
    static readonly string RxRansomExt = D("KD9pKVwuKD86bG9ja2VkfGNyeXB0fGNyeXB0ZWR8ZW5jcnlwdGVkfHduY3J5fGxvY2tiaXR8Y29udGl8YWtpcmF8YmFieWt8YmxhY2tjYXR8cm95YWwpXGI=");
    static readonly string RxMacVm = D("KD9pKVxiKD86MDhbOlwtXTAwWzpcLV0yN3wwMFs6XC1dMGNbOlwtXTI5fDAwWzpcLV01MFs6XC1dNTZ8MDBbOlwtXTA1WzpcLV02OXwwMFs6XC1dMWNbOlwtXTE0fDBhWzpcLV0wMFs6XC1dMjcpKD86WzpcLV1bMC05YS1mXXsyfSl7MCwzfVxi");

    static readonly string[] NetLibs =
    {
        "socket", "requests", "urllib", "urllib3", "http.client", "httpx", "aiohttp", "websocket", "websockets",
        "ftplib", "smtplib", "paramiko", "telnetlib", "pycurl",
    };

    static readonly string[] CryptoLibs = { "cryptography", "Crypto", "Cryptodome", "nacl", "pyaes", "rsa" };

    static readonly string[] WalkNames = { "walk", "scandir", "glob", "iterdir", "rglob", "listdir" };

    static readonly List<Rule> Rules = BuildRules();

    static List<Rule> BuildRules() => new()
    {
        // Execution and loading
        R("loader", "Loader", "Execution", Sus,
          D("RGVjb2RlcywgZGVjcnlwdHMgb3IgZG93bmxvYWRzIGRhdGEsIHRoZW4gcnVucyBpdCB0aHJvdWdoIGV4ZWMvZXZhbC4="),
          G(N(D("ZXhlYw=="), D("ZXZhbA=="))),
          G(N(D("YjY0ZGVjb2Rl"), D("Yjg1ZGVjb2Rl"), D("YTg1ZGVjb2Rl"), D("YjMyZGVjb2Rl"), D("YjE2ZGVjb2Rl"), D("YTJiX2Jhc2U2NA=="), D("dW5oZXhsaWZ5"), D("ZnJvbWhleA=="),
              D("dXJsb3Blbg=="), D("dXJscmV0cmlldmU="), D("ZGVjcnlwdA=="))))
         .Boost(Mal, G(N(D("ZGVjb21wcmVzcw=="), D("ZGVjb21wcmVzc29iag=="), D("bG9hZHM="), D("dXJsb3Blbg=="), D("dXJscmV0cmlldmU="), D("ZGVjcnlwdA==")))),

        R("marshal-loader", "Marshal code loading", "Execution", Sus,
          D("TG9hZHMgYSBzZXJpYWxpemVkIGNvZGUgb2JqZWN0IHdpdGggbWFyc2hhbC5sb2FkcyBhbmQgcnVucyBpdCAoY2xhc3NpYyBwYWNrZWQtcHljIGxvYWRlciku"),
          G(M(D("bWFyc2hhbA=="))), G(N(D("bG9hZHM="))), G(N(D("ZXhlYw=="), D("ZXZhbA=="))))
         .Boost(Mal, G(N(D("YjY0ZGVjb2Rl"), D("Yjg1ZGVjb2Rl"), D("YTg1ZGVjb2Rl"), D("dW5oZXhsaWZ5"), D("ZGVjb21wcmVzcw=="), D("ZGVjb21wcmVzc29iag=="),
                         D("dXJsb3Blbg=="), D("dXJscmV0cmlldmU="), D("ZGVjcnlwdA==")))),

        R("remote-exec", "Remote code execution", "Execution", Sus,
          D("RmV0Y2hlcyBkYXRhIGZyb20gdGhlIG5ldHdvcmsgKEhUVFAgb3Igc29ja2V0KSBhbmQgcGFzc2VzIGNvZGUgdGhyb3VnaCBleGVjL2V2YWwu"),
          G(N(D("ZXhlYw=="), D("ZXZhbA=="))), G(M(NetLibs)),
          G(N(D("dXJsb3Blbg=="), D("dXJscmV0cmlldmU="), D("Z2V0"), D("cG9zdA=="), D("cmVhZA=="), D("dGV4dA=="), D("Y29udGVudA=="), D("cmVjdg=="))))
         .Boost(Mal, G(X(RxRawIpUrl), S(D("cGFzdGViaW4uY29tL3Jhdw=="), D("cmF3LmdpdGh1YnVzZXJjb250ZW50LmNvbQ=="), D("Z2lzdC5naXRodWJ1c2VyY29udGVudC5jb20="),
                                        D("Y2RuLmRpc2NvcmRhcHAuY29tL2F0dGFjaG1lbnRz"), D("cGFzdGUuZWUvcg=="), D("aGFzdGViaW4uY29tL3Jhdw=="), D("cmVudHJ5LmNvLw=="),
                                        D("dHJhbnNmZXIuc2g="), D("Y2F0Ym94Lm1vZQ==")))),

        R("hidden-code-object", "Hidden code object", "Obfuscation", Sus,
          D("QSBtYXJzaGFsbGVkIGNvZGUgb2JqZWN0IGlzIGhpZGRlbiBpbnNpZGUgYSBjb25zdGFudCAocmF3LCBjb21wcmVzc2VkLCBvciBiYXNlNjQvaGV4LWVuY29kZWQpLg=="),
          G(S(MarshalMarker)))
         .Boost(Mal, G(N(D("bG9hZHM="))), G(N(D("ZXhlYw=="), D("ZXZhbA==")))),

        R("dynamic-exec", "Dynamic code execution", "Execution", Inf,
          D("Q2FsbHMgZXhlYygpLCBldmFsKCkgb3IgX19pbXBvcnRfXygpLg=="),
          G(N(D("ZXhlYw=="), D("ZXZhbA=="), D("X19pbXBvcnRfXw==")))),

        R("shell-exec", "Process / shell execution", "Execution", Inf,
          D("TGF1bmNoZXMgcHJvY2Vzc2VzIG9yIGEgc2hlbGwgKHN1YnByb2Nlc3MsIFBvcGVuLCBTaGVsbEV4ZWN1dGUsIFdpbkV4ZWMsIGV4ZWMqL3NwYXduKiku"),
          G(M(D("c3VicHJvY2Vzcw=="), D("cHR5")), N(D("UG9wZW4="), D("Y2hlY2tfb3V0cHV0"), D("Y2hlY2tfY2FsbA=="), D("c3RhcnRmaWxl"), D("U2hlbGxFeGVjdXRl"), D("U2hlbGxFeGVjdXRlVw=="),
                                       D("U2hlbGxFeGVjdXRlRXhX"), D("V2luRXhlYw=="), D("Q3JlYXRlUHJvY2Vzcw=="), D("Q3JlYXRlUHJvY2Vzc1c="), D("Q3JlYXRlUHJvY2Vzc0E="),
                                       D("ZXhlY3Y="), D("ZXhlY3Zl"), D("ZXhlY2w="), D("ZXhlY2xw"), D("ZXhlY3Zw"), D("c3Bhd25s"), D("c3Bhd252"), D("cG9zaXhfc3Bhd24=")))),

        R("os-system", "os.system / popen", "Execution", Inf,
          D("UnVucyBzaGVsbCBjb21tYW5kcyB0aHJvdWdoIG9zLnN5c3RlbSBvciBvcy5wb3Blbi4="),
          G(M(D("b3M="))), G(N(D("c3lzdGVt"), D("cG9wZW4=")))),

        R("powershell", "PowerShell", "Execution", Inf,
          D("UnVucyBQb3dlclNoZWxsOyBiZWNvbWVzIHN1c3BpY2lvdXMgd2hlbiBlbmNvZGVkLCBoaWRkZW4sIHBvbGljeS1ieXBhc3Npbmcgb3IgZG93bmxvYWRpbmcu"),
          G(S(D("cG93ZXJzaGVsbA=="), D("cHdzaC5leGU="))))
         .Boost(Sus, G(S(D("LWVuY29kZWRjb21tYW5k"), D("LWVuYyA="), D("LWVjIA=="), D("LWV4ZWN1dGlvbnBvbGljeSBieXBhc3M="), D("LWVwIGJ5cGFzcw=="), D("LW5vcA=="),
                         D("LXdpbmRvd3N0eWxlIGhpZGRlbg=="), D("LXcgaGlkZGVu"), D("aW52b2tlLWV4cHJlc3Npb24="), D("aWV4KA=="), D("aWV4IA=="), D("ZG93bmxvYWRzdHJpbmc="),
                         D("ZG93bmxvYWRmaWxl"), D("aW52b2tlLXdlYnJlcXVlc3Q="), D("aXdyIA=="), D("ZnJvbWJhc2U2NHN0cmluZw=="), D("c3RhcnQtYml0c3RyYW5zZmVy"),
                         D("bmV0LndlYmNsaWVudA=="), D("W3JlZmxlY3Rpb24uYXNzZW1ibHldOjpsb2Fk")))),

        R("amsi-bypass", "AMSI / ETW bypass", "Defense evasion", Mal,
          D("UmVmZXJlbmNlcyBBTVNJIG9yIEVUVyBwYXRjaGluZyB0ZWNobmlxdWVzIHVzZWQgdG8gYmxpbmQgc2VjdXJpdHkgdG9vbGluZy4="),
          G(S(D("YW1zaXNjYW5idWZmZXI="), D("YW1zaWluaXRmYWlsZWQ="), D("YW1zaXV0aWxz"), D("ZXR3ZXZlbnR3cml0ZQ=="), D("YW1zaWNvbnRleHQ=")))),

        R("lolbin", "LOLBin usage", "Execution", Inf,
          D("VXNlcyBsZWdpdGltYXRlIFdpbmRvd3MgYmluYXJpZXMgKGNlcnR1dGlsLCBiaXRzYWRtaW4sIG1zaHRhLCBydW5kbGwzMiwgcmVnc3ZyMzIsIHdtaWMuLi4pOyBzdXNwaWNpb3VzIHdoZW4gY29tYmluZWQgd2l0aCBVUkxzLCBkZWNvZGluZyBvciBzY3JpcHQgcHJvdG9jb2xzLg=="),
          G(S(D("Y2VydHV0aWw="), D("Yml0c2FkbWlu"), D("bXNodGE="), D("cnVuZGxsMzI="), D("cmVnc3ZyMzI="), D("aW5zdGFsbHV0aWw="), D("bXNidWlsZC5leGU="), D("d21pYyA="),
              D("Y3NjcmlwdA=="), D("d3NjcmlwdA=="), D("Zm9yZmlsZXM="), D("bXNpZXhlYyAvaQ=="))))
         .Boost(Sus, G(S(D("aHR0cDovLw=="), D("aHR0cHM6Ly8="), D("LXVybGNhY2hl"), D("LWRlY29kZQ=="), D("c2Nyb2JqLmRsbA=="), D("amF2YXNjcmlwdDo="), D("dmJzY3JpcHQ6"),
                         D("L3RyYW5zZmVy"), D("cHJvY2VzcyBjYWxsIGNyZWF0ZQ=="), D("L2k6aHR0cA==")))),

        R("injection", "Process injection", "Execution", Sus,
          D("VXNlcyBjcm9zcy1wcm9jZXNzIG1lbW9yeS90aHJlYWQgQVBJcyAoV3JpdGVQcm9jZXNzTWVtb3J5LCBDcmVhdGVSZW1vdGVUaHJlYWQsIEFQQywgaG9sbG93aW5nLi4uKS4="),
          G(N(D("V3JpdGVQcm9jZXNzTWVtb3J5"), D("Q3JlYXRlUmVtb3RlVGhyZWFk"), D("Q3JlYXRlUmVtb3RlVGhyZWFkRXg="), D("TnRVbm1hcFZpZXdPZlNlY3Rpb24="),
              D("WndVbm1hcFZpZXdPZlNlY3Rpb24="), D("UXVldWVVc2VyQVBD"), D("TnRRdWV1ZUFwY1RocmVhZA=="), D("U2V0VGhyZWFkQ29udGV4dA=="), D("TnRDcmVhdGVUaHJlYWRFeA=="),
              D("TnRXcml0ZVZpcnR1YWxNZW1vcnk="), D("VmlydHVhbEFsbG9jRXg="))))
         .Boost(Mal, G(N(D("V3JpdGVQcm9jZXNzTWVtb3J5"), D("TnRXcml0ZVZpcnR1YWxNZW1vcnk="))),
                     G(N(D("Q3JlYXRlUmVtb3RlVGhyZWFk"), D("Q3JlYXRlUmVtb3RlVGhyZWFkRXg="), D("TnRDcmVhdGVUaHJlYWRFeA=="), D("UXVldWVVc2VyQVBD"), D("TnRRdWV1ZUFwY1RocmVhZA=="),
                         D("U2V0VGhyZWFkQ29udGV4dA=="), D("UmVzdW1lVGhyZWFk"), D("TnRVbm1hcFZpZXdPZlNlY3Rpb24="), D("WndVbm1hcFZpZXdPZlNlY3Rpb24="))))
         .Near(),

        R("shellcode", "Shellcode / in-memory execution", "Execution", Mal,
          D("QWxsb2NhdGVzIGV4ZWN1dGFibGUgbWVtb3J5LCB0aGVuIGNvcGllcyBvciBydW5zIGNvZGUgZnJvbSBpdC4="),
          G(N(D("VmlydHVhbEFsbG9j"), D("VmlydHVhbFByb3RlY3Q="), D("UEFHRV9FWEVDVVRFX1JFQURXUklURQ=="), D("UFJPVF9FWEVD"))),
          G(N(D("UnRsTW92ZU1lbW9yeQ=="), D("bWVtbW92ZQ=="), D("Q3JlYXRlVGhyZWFk"), D("Q0ZVTkNUWVBF"), D("V0lORlVOQ1RZUEU="))))
         .Near(),

        R("native-api", "Direct native API calls", "Native code", Sus,
          D("Q2FsbHMgbG93LWxldmVsIE50Ki9adyovTGRyKiBmdW5jdGlvbnMgZGlyZWN0bHksIHdoaWNoIGlzIHJhcmUgaW4gbGVnaXRpbWF0ZSBQeXRob24gY29kZS4="),
          G(N(D("TnRBbGxvY2F0ZVZpcnR1YWxNZW1vcnk="), D("TnRQcm90ZWN0VmlydHVhbE1lbW9yeQ=="), D("TnRDcmVhdGVTZWN0aW9u"), D("TnRNYXBWaWV3T2ZTZWN0aW9u"),
              D("TnRDcmVhdGVVc2VyUHJvY2Vzcw=="), D("TnRPcGVuUHJvY2Vzcw=="), D("WndBbGxvY2F0ZVZpcnR1YWxNZW1vcnk="), D("TGRyTG9hZERsbA=="), D("UnRsQ3JlYXRlVXNlclRocmVhZA=="),
              D("TnRMb2FkRHJpdmVy"), D("WndMb2FkRHJpdmVy")))),

        R("embedded-exe", "Embedded executable", "Execution", Mal,
          D("QSBjb25zdGFudCAocmF3IG9yIGhpZGRlbiBiZWhpbmQgYmFzZTY0L2hleC9jb21wcmVzc2lvbikgY29udGFpbnMgYW4gZW1iZWRkZWQgUEUgb3IgRUxGIGV4ZWN1dGFibGUu"),
          G(X(RxPeHeader), X(RxElfHeader), S(D("dHZxcWFhbWFhYWFlYWFhYQ==")))),

        R("embedded-archive", "Embedded archive", "Execution", Inf,
          D("QSBjb25zdGFudCBjb250YWlucyBhIFpJUC9SQVIvN3ogYXJjaGl2ZTsgc3VzcGljaW91cyB3aGVuIHRoZSBwcm9ncmFtIGFsc28gbGF1bmNoZXMgcHJvY2Vzc2VzIG9yIGV4dHJhY3RzIGl0Lg=="),
          G(X(RxArchiveHeader)))
         .Boost(Sus, G(N(D("ZXh0cmFjdGFsbA=="), D("WmlwRmlsZQ=="), D("UG9wZW4="), D("c3RhcnRmaWxl"), D("U2hlbGxFeGVjdXRl"), D("U2hlbGxFeGVjdXRlVw=="), D("Q3JlYXRlUHJvY2Vzcw=="),
                         D("Q3JlYXRlUHJvY2Vzc1c=")))),

        R("opaque-blob", "Encrypted / compressed blob", "Obfuscation", Inf,
          D("TGFyZ2UgaGlnaC1lbnRyb3B5IGJpbmFyeSBjb25zdGFudCAoZW5jcnlwdGVkIG9yIGNvbXByZXNzZWQgZGF0YTsgY29tbW9uIGltYWdlL2F1ZGlvIGZvcm1hdHMgYXJlIGlnbm9yZWQpLg=="),
          G(E()))
         .Boost(Sus, G(N(D("ZXhlYw=="), D("ZXZhbA=="), D("bG9hZHM="), D("ZGVjcnlwdA=="), D("ZGVjb21wcmVzcw=="), D("ZGVjb21wcmVzc29iag=="), D("VmlydHVhbEFsbG9j"), D("Q0ZVTkNUWVBF"),
                         D("Q3JlYXRlVGhyZWFk")))),

        // Obfuscation / encoding
        R("base64", "Base64", "Encoding", Inf,
          D("VXNlcyBiYXNlNjQgb3IgZW1iZWRzIGxhcmdlIGJhc2U2NC1saWtlIGJsb2JzLg=="),
          G(M(D("YmFzZTY0")), N(D("YjY0ZGVjb2Rl"), D("YjY0ZW5jb2Rl"), D("dXJsc2FmZV9iNjRkZWNvZGU="), D("dXJsc2FmZV9iNjRlbmNvZGU="), D("c3RhbmRhcmRfYjY0ZGVjb2Rl"),
                            D("YjMyZGVjb2Rl"), D("Yjg1ZGVjb2Rl"), D("YTg1ZGVjb2Rl")), X(RxBase64))),

        R("packed", "Packed / encoded payload", "Obfuscation", Inf,
          D("Q29tYmluZXMgbWFyc2hhbC96bGliL2x6bWEvYnoyIHdpdGggYmFzZTY0OyBzdXNwaWNpb3VzIHdoZW4gYSBsYXJnZSBlbmNvZGVkIGJsb2IgaXMgcHJlc2VudC4="),
          G(M(D("bWFyc2hhbA=="), D("emxpYg=="), D("bHptYQ=="), D("Ynoy"))),
          G(M(D("YmFzZTY0"), D("YmluYXNjaWk=")), N(D("YjY0ZGVjb2Rl"), D("Yjg1ZGVjb2Rl"), D("YTg1ZGVjb2Rl"), D("dW5oZXhsaWZ5"))))
         .Boost(Sus, G(X(RxBase64), E())),

        R("pyarmor", "PyArmor / obfuscator", "Obfuscation", Inf,
          D("TWFya2VycyBhc3NvY2lhdGVkIHdpdGggUHlBcm1vciBvciBhbm90aGVyIFB5dGhvbiBvYmZ1c2NhdG9yLg=="),
          G(M(D("cHl0cmFuc2Zvcm0="), D("cHlhcm1vcl9ydW50aW1l"), D("X3B5dHJhbnNmb3Jt")),
            N(D("X19weWFybW9yX18="), D("cHlhcm1vcl9ydW50aW1l"), D("X19hcm1vcl9lbnRlcl9f"), D("X19hcm1vcl9leGl0X18=")),
            S(D("X19weWFybW9yX18="), D("cHl0cmFuc2Zvcm0="), D("cHlhcm1vcl9ydW50aW1l"), D("cHlvYmZ1c2NhdGU="), D("cHltaW5pZmllcg=="), D("cHlmdXNjYXRpb24=")))),

        R("string-obfuscation", "Character-code obfuscation", "Obfuscation", Inf,
          D("QnVpbGRzIGNvZGUgZnJvbSBjaGFyYWN0ZXIgY29kZXMgKGNoci9qb2luKSBhbmQgZXhlY3V0ZXMgaXQu"),
          G(N(D("ZXhlYw=="), D("ZXZhbA=="))), G(N(D("Y2hy"))), G(N(D("am9pbg=="))))
         .Boost(Sus, G(N(D("cmVkdWNl"), D("bWFw"), D("ZnJvbWhleA=="), D("Ynl0ZWFycmF5"), D("dW5oZXhsaWZ5"), D("YjY0ZGVjb2Rl"), D("ZGVjb21wcmVzcw==")))),

        R("builtins-access", "Builtins indirection", "Obfuscation", Inf,
          D("UmVhY2hlcyBleGVjL2V2YWwvX19pbXBvcnRfXyB0aHJvdWdoIF9fYnVpbHRpbnNfXyBhbmQgZ2V0YXR0ciB0byBoaWRlIGRpcmVjdCBjYWxscy4="),
          G(N(D("X19idWlsdGluc19f"), D("YnVpbHRpbnM="))), G(N(D("Z2V0YXR0cg=="), D("X19nZXRhdHRyaWJ1dGVfXw=="), D("dmFycw=="), D("Z2xvYmFscw=="))),
          G(N(D("ZXhlYw=="), D("ZXZhbA=="), D("Y29tcGlsZQ=="), D("X19pbXBvcnRfXw=="))))
         .Boost(Sus, G(N(D("Y2hy"), D("YjY0ZGVjb2Rl"), D("ZGVjb21wcmVzcw=="), D("dW5oZXhsaWZ5"), D("ZnJvbWhleA=="), D("ZGVjb2Rl")))),

        R("codec-obfuscation", "ROT13 / codec obfuscation", "Obfuscation", Sus,
          D("VXNlcyByb3QxMy1zdHlsZSBjb2RlY3MgdG9nZXRoZXIgd2l0aCBleGVjL2V2YWwu"),
          G(S(D("cm90XzEz"), D("cm90MTM="))), G(N(D("ZXhlYw=="), D("ZXZhbA==")))),

        R("encryption", "Cryptography", "Encoding", Inf,
          D("VXNlcyBhIGNyeXB0b2dyYXBoeSBsaWJyYXJ5IChjcnlwdG9ncmFwaHksIFB5Q3J5cHRvZG9tZSwgUHlOYUNsLi4uKS4="),
          G(M(CryptoLibs), N(D("RmVybmV0")))),

        // System, privileges, persistence
        R("registry", "Registry actions", "System", Inf,
          D("UmVhZHMgb3Igd3JpdGVzIHRoZSBXaW5kb3dzIHJlZ2lzdHJ5ICh3aW5yZWcsIHJlZy5leGUsIEhLRVlfKiBwYXRocyku"),
          G(M(D("d2lucmVn"), D("X3dpbnJlZw==")),
            N(D("T3BlbktleQ=="), D("T3BlbktleUV4"), D("Q3JlYXRlS2V5"), D("Q3JlYXRlS2V5RXg="), D("U2V0VmFsdWVFeA=="), D("RGVsZXRlS2V5"), D("RGVsZXRlVmFsdWU="),
              D("UmVnU2V0VmFsdWVFeA=="), D("UmVnQ3JlYXRlS2V5RXg="), D("UmVnT3BlbktleUV4"), D("SEtFWV9DVVJSRU5UX1VTRVI="), D("SEtFWV9MT0NBTF9NQUNISU5F")),
            S(D("aGtleV9jdXJyZW50X3VzZXI="), D("aGtleV9sb2NhbF9tYWNoaW5l"), D("aGtjdVw="), D("aGtsbVw="), D("cmVnIGFkZA=="), D("cmVnIGRlbGV0ZQ=="), D("cmVnIHF1ZXJ5"), D("cmVnLmV4ZQ==")))),

        R("system-tamper", "System policy tampering", "Defense evasion", Sus,
          D("RGlzYWJsZXMgVGFzayBNYW5hZ2VyL3JlZ2lzdHJ5IHRvb2xzLCBVQUMgcHJvbXB0cyBvciBob29rcyBJbWFnZSBGaWxlIEV4ZWN1dGlvbiBPcHRpb25zLg=="),
          G(S(D("aW1hZ2UgZmlsZSBleGVjdXRpb24gb3B0aW9ucw=="), D("ZGlzYWJsZXRhc2ttZ3I="), D("ZGlzYWJsZXJlZ2lzdHJ5dG9vbHM="), D("ZW5hYmxlbHVh"),
              D("Y29uc2VudHByb21wdGJlaGF2aW9yYWRtaW4="), D("aGlkZWZpbGVleHQ="), D("cG9saWNpZXNcZXhwbG9yZXJcbm9kcml2ZXM=")))),

        R("persistence", "Persistence", "Persistence", Sus,
          D("SW5zdGFsbHMgaXRzZWxmIHRvIHJ1biBhdXRvbWF0aWNhbGx5IChSdW4ga2V5LCBTdGFydHVwIGZvbGRlciwgc2NoZWR1bGVkIHRhc2ssIGNyb24sIGxhdW5jaCBhZ2VudHMsIHN5c3RlbWQsIFdNSSku"),
          G(S(D("Y3VycmVudHZlcnNpb25ccnVu"), D("Y3VycmVudHZlcnNpb25ccnVub25jZQ=="), D("Y3VycmVudHZlcnNpb25cd2lubG9nb24="), D("c3RhcnQgbWVudVxwcm9ncmFtc1xzdGFydHVw"),
              D("c2hlbGw6c3RhcnR1cA=="), D("L2V0Yy9jcm9udGFi"), D("L2V0Yy9jcm9uLmQ="), D("L3Zhci9zcG9vbC9jcm9u"), D("QHJlYm9vdA=="), D("L2V0Yy9yYy5sb2NhbA=="),
              D("LmNvbmZpZy9hdXRvc3RhcnQ="), D("bGF1bmNoYWdlbnRz"), D("bGF1bmNoZGFlbW9ucw=="), D("c3lzdGVtY3RsIGVuYWJsZQ=="), D("L2V0Yy9zeXN0ZW1kL3N5c3RlbS8="),
              D("L2V0Yy9pbml0LmQv"), D("YXBwaW5pdF9kbGxz"), D("X19ldmVudGZpbHRlcg=="), D("Y29tbWFuZGxpbmVldmVudGNvbnN1bWVy")),
            X(D("KD9pKXNjaHRhc2tzKD86XC5leGUpP1xzKy9jcmVhdGU=")),
            N(D("YWRkX3RvX3N0YXJ0dXA="), D("YWRkX3N0YXJ0dXA="), D("c3RhcnR1cF9hZGQ="), D("aW5zdGFsbF9wZXJzaXN0ZW5jZQ==")))),

        R("service-install", "Service installation", "Persistence", Inf,
          D("Q3JlYXRlcyBvciByZWdpc3RlcnMgYSBXaW5kb3dzIHNlcnZpY2Uu"),
          G(N(D("Q3JlYXRlU2VydmljZQ=="), D("Q3JlYXRlU2VydmljZVc="), D("T3BlblNDTWFuYWdlcg=="), D("T3BlblNDTWFuYWdlclc="), D("SW5zdGFsbFNlcnZpY2U=")),
            X(D("KD9pKSg/PCFbYS16XSlzYyg/OlwuZXhlKT9ccytjcmVhdGVccw==")), S(D("bmV3LXNlcnZpY2U=")))),

        R("admin", "Administrator required", "Privileges", Inf,
          D("Q2hlY2tzIGZvciBhZG1pbmlzdHJhdG9yIHByaXZpbGVnZXMgb3IgcmVxdWVzdHMgZWxldmF0aW9uIChJc1VzZXJBbkFkbWluLCBydW5hcywgcmVxdWlyZUFkbWluaXN0cmF0b3IpLg=="),
          G(N(D("SXNVc2VyQW5BZG1pbg=="), D("aXNfYWRtaW4="), D("aXNhZG1pbg=="), D("cnVuX2FzX2FkbWlu"), D("cnVuYXNfYWRtaW4="), D("Y2hlY2tfYWRtaW4="), D("cmVsYXVuY2hfYXNfYWRtaW4=")),
            X(RxRunAs),
            S(D("aXN1c2VyYW5hZG1pbg=="), D("cmVxdWlyZWFkbWluaXN0cmF0b3I="), D("aGlnaGVzdGF2YWlsYWJsZQ=="), D("cy0xLTUtMzItNTQ0"), D("bmV0IHNlc3Npb24="),
              D("bmV0LmV4ZSBzZXNzaW9u"), D("d2hvYW1pIC9ncm91cHM=")))),

        R("privilege-escalation", "Token / privilege manipulation", "Privileges", Sus,
          D("RW5hYmxlcyBkYW5nZXJvdXMgcHJpdmlsZWdlcyAoU2VEZWJ1ZywgU2VMb2FkRHJpdmVyLCBTZUltcGVyc29uYXRlLi4uKSB2aWEgdG9rZW4gQVBJcy4="),
          G(S(D("c2VkZWJ1Z3ByaXZpbGVnZQ=="), D("c2Vsb2FkZHJpdmVycHJpdmlsZWdl"), D("c2V0Y2Jwcml2aWxlZ2U="), D("c2VpbXBlcnNvbmF0ZXByaXZpbGVnZQ=="))),
          G(N(D("QWRqdXN0VG9rZW5Qcml2aWxlZ2Vz"), D("SW1wZXJzb25hdGVMb2dnZWRPblVzZXI="), D("RHVwbGljYXRlVG9rZW5FeA=="), D("Q3JlYXRlUHJvY2Vzc0FzVXNlcg=="),
              D("Q3JlYXRlUHJvY2Vzc1dpdGhUb2tlblc="), D("U2V0VGhyZWFkVG9rZW4="), D("SW1wZXJzb25hdGVOYW1lZFBpcGVDbGllbnQ=")))),

        R("uac-bypass", "UAC bypass", "Privileges", Sus,
          D("UmVmZXJlbmNlcyBhdXRvLWVsZXZhdGVkIGJpbmFyaWVzIG9yIGhpamFja2FibGUga2V5cyB1c2VkIHRvIGJ5cGFzcyBVQUMu"),
          G(S(D("Zm9kaGVscGVy"), D("ZXZlbnR2d3IuZXhl"), D("Y29tcHV0ZXJkZWZhdWx0cw=="), D("c2RjbHQuZXhl"), D("Y21zdHAuZXhl"),
              D("bXMtc2V0dGluZ3Ncc2hlbGxcb3Blblxjb21tYW5k"), D("bXNjZmlsZVxzaGVsbFxvcGVuXGNvbW1hbmQ="), D("ZGVsZWdhdGVleGVjdXRl"))))
         .Boost(Mal, G(M(D("d2lucmVn"), D("X3dpbnJlZw==")), N(D("U2V0VmFsdWVFeA=="), D("Q3JlYXRlS2V5"), D("Q3JlYXRlS2V5RXg="), D("UmVnU2V0VmFsdWVFeA==")), S(D("cmVnIGFkZA==")))),

        R("user-account-tamper", "User account creation", "Persistence", Sus,
          D("Q3JlYXRlcyBhIHVzZXIgb3IgYWRkcyBvbmUgdG8gdGhlIGFkbWluaXN0cmF0b3JzIGdyb3VwIHRocm91Z2ggbmV0LmV4ZS4="),
          G(X(D("KD9pKVxibmV0MT9ccyt1c2VyXHMrXFMrW15cclxuXXswLDYwfS9hZGRcYg==")),
            X(D("KD9pKVxibmV0MT9ccytsb2NhbGdyb3VwXHMrYWRtaW5pc3RyYXRvcnM/XHMrXFMrXHMqL2FkZFxi")))),

        R("defender-tamper", "Disables security tools", "Defense evasion", Mal,
          D("VHVybnMgb2ZmIFdpbmRvd3MgRGVmZW5kZXIgcmVhbC10aW1lIHByb3RlY3Rpb24sIHNlcnZpY2VzIG9yIHRoZSBmaXJld2FsbC4="),
          G(S(D("ZGlzYWJsZXJlYWx0aW1lbW9uaXRvcmluZw=="), D("ZGlzYWJsZWFudGlzcHl3YXJl"), D("d2luZG93cyBkZWZlbmRlclxyZWFsLXRpbWUgcHJvdGVjdGlvbg=="),
              D("d2luZG93cyBkZWZlbmRlclxleGNsdXNpb25z"), D("cG9saWNpZXNcbWljcm9zb2Z0XHdpbmRvd3MgZGVmZW5kZXI="), D("c2Mgc3RvcCB3aW5kZWZlbmQ="),
              D("c2MgY29uZmlnIHdpbmRlZmVuZA=="), D("bmV0IHN0b3Agd2luZGVmZW5k"), D("c3RvcC1zZXJ2aWNlIHdpbmRlZmVuZA=="), D("bmV0c2ggYWR2ZmlyZXdhbGwgc2V0IGFsbHByb2ZpbGVzIHN0YXRlIG9mZg=="),
              D("bmV0c2ggZmlyZXdhbGwgc2V0IG9wbW9kZSBkaXNhYmxl"), D("ZGlzYWJsZWlvYXZwcm90ZWN0aW9u"), D("ZGlzYWJsZWJsb2NrYXRmaXJzdHNlZW4="), D("dGFtcGVycHJvdGVjdGlvbg==")))),

        R("defender-exclusion", "Defender exclusions", "Defense evasion", Sus,
          D("QWRkcyBXaW5kb3dzIERlZmVuZGVyIGV4Y2x1c2lvbnMgKHBhdGhzLCBleHRlbnNpb25zLCBwcm9jZXNzZXMpLg=="),
          G(S(D("YWRkLW1wcHJlZmVyZW5jZQ=="), D("ZXhjbHVzaW9ucGF0aA=="), D("ZXhjbHVzaW9uZXh0ZW5zaW9u"), D("ZXhjbHVzaW9ucHJvY2Vzcw==")))),

        R("security-product-kill", "Kills security products", "Defense evasion", Sus,
          D("TGlzdHMgYW50aXZpcnVzL0VEUiBwcm9jZXNzIG9yIHNlcnZpY2UgbmFtZXMgYW5kIHN0b3BzIHRoZW0u"),
          G(S(D("bXNtcGVuZw=="), D("bXBjbWRydW4="), D("bXNzZWNlcw=="), D("bWJhbS5leGU="), D("bWJhbXNlcnZpY2U="), D("YXZwLmV4ZQ=="), D("YXZndWk="), D("YXZndWFyZA=="), D("YXZnbnQ="),
              D("YmRhZ2VudA=="), D("YmRzZXJ2aWNlaG9zdA=="), D("ZWd1aS5leGU="), D("ZWtybi5leGU="), D("bWNzaGllbGQ="), D("bWZldnRwcw=="), D("c29waG9zZnM="), D("c2F2c2VydmljZQ=="),
              D("d3JzYS5leGU="), D("Y3NmYWxjb25zZXJ2aWNl"), D("Y3NmYWxjb25jb250YWluZXI="), D("c2VudGluZWxhZ2VudA=="), D("c2VudGluZWxzZXJ2aWNlaG9zdA=="), D("Y3lsYW5jZXN2Yw=="),
              D("c2VjdXJpdHloZWFsdGhzZXJ2aWNl"), D("d2luZGVmZW5k"))),
          G(S(D("dGFza2tpbGw="), D("c2Mgc3RvcA=="), D("bmV0IHN0b3A="), D("c2MgZGVsZXRl"), D("c2MgY29uZmln")), N(D("VGVybWluYXRlUHJvY2Vzcw=="), D("a2lsbA=="), D("dGVybWluYXRl"))))
         .Min(2),

        R("anti-debug", "Anti-debugging", "Defense evasion", Inf,
          D("Q2hlY2tzIGZvciBhbiBhdHRhY2hlZCBkZWJ1Z2dlciBvciBzZXRzIHRyYWNlIGhvb2tzLg=="),
          G(N(D("SXNEZWJ1Z2dlclByZXNlbnQ="), D("Q2hlY2tSZW1vdGVEZWJ1Z2dlclByZXNlbnQ="), D("TnRRdWVyeUluZm9ybWF0aW9uUHJvY2Vzcw=="), D("T3V0cHV0RGVidWdTdHJpbmc="),
              D("c2V0dHJhY2U="), D("Z2V0dHJhY2U="), D("UHJvY2Vzc0RlYnVnUG9ydA=="), D("TnRTZXRJbmZvcm1hdGlvblRocmVhZA==")))),

        R("anti-vm", "Anti-VM / sandbox artifacts", "Defense evasion", Sus,
          D("Q2hlY2tzIHNldmVyYWwgdmlydHVhbCBtYWNoaW5lIG9yIHNhbmRib3ggYXJ0aWZhY3RzIChkcml2ZXJzLCBzZXJ2aWNlcywgRExMcywgTUFDIHByZWZpeGVzKS4="),
          G(S(D("dmJveHNlcnZpY2U="), D("dmJveHRyYXk="), D("dmJveGd1ZXN0"), D("dmJveG1vdXNl"), D("dmJveHNm"), D("dmJveGhvb2suZGxs"), D("dmJveGRpc3AuZGxs"), D("dmJveG9nbA=="),
              D("dm10b29sc2Q="), D("dm13YXJldHJheQ=="), D("dm13YXJldXNlcg=="), D("dm11c3J2Yw=="), D("dm1zcnZj"), D("dm1tb3VzZQ=="), D("dm1oZ2Zz"), D("dm0zZGds"), D("dm14X3N2Z2E="),
              D("cWVtdS1nYQ=="), D("eGVuc2VydmljZQ=="), D("cHJsX2Nj"), D("cHJsX3Rvb2xz"), D("c2JpZWRsbA=="), D("c2JpZWRydg=="), D("c2FuZGJveGll"), D("Y21kdnJ0MzIuZGxs"),
              D("Y21kdnJ0NjQuZGxs"), D("c254aGsuZGxs"), D("YXZnaG9va3guZGxs"), D("YXZnaG9va2EuZGxs"), D("YXBpX2xvZy5kbGw="), D("ZGlyX3dhdGNoLmRsbA=="), D("cHN0b3JlYy5kbGw="),
              D("dm1jaGVjay5kbGw="), D("d3Blc3B5LmRsbA=="), D("d2RhZ3V0aWxpdHlhY2NvdW50"), D("dGVxdWlsYWJvb21ib29t")),
            X(RxMacVm)))
         .Min(2),

        R("anti-analysis-tools", "Analysis tool detection", "Defense evasion", Sus,
          D("RW51bWVyYXRlcyBwcm9jZXNzZXMgYW5kIGNvbXBhcmVzIHRoZW0gYWdhaW5zdCBhIGxpc3Qgb2YgcmV2ZXJzZS1lbmdpbmVlcmluZyBvciBtb25pdG9yaW5nIHRvb2xzLg=="),
          G(S(D("b2xseWRiZw=="), D("eDY0ZGJn"), D("eDMyZGJn"), D("cHJvY2Vzc2hhY2tlcg=="), D("cHJvY21vbg=="), D("cHJvY2V4cA=="), D("d2lyZXNoYXJr"), D("ZmlkZGxlcg=="), D("aWRhNjQ="),
              D("aWRhcQ=="), D("ZG5zcHk="), D("cGVzdHVkaW8="), D("aHR0cGRlYnVnZ2Vy"), D("d2luZGJn"), D("aW1tdW5pdHk="), D("c2N5bGxh"), D("cmVnbW9u"), D("ZmlsZW1vbg=="), D("dGNwdmlldw=="),
              D("YXBpbW9uaXRvcg=="), D("aG9va2V4cGxvcmVy"), D("aW1wb3J0cmVj"), D("cGV0b29scw=="), D("bG9yZHBl"), D("c3lzYW5hbHl6ZXI="), D("Y3Vja29v"), D("am9lYm94Y29udHJvbA=="))),
          G(N(D("cHJvY2Vzc19pdGVy"), D("RW51bVByb2Nlc3Nlcw=="), D("Q3JlYXRlVG9vbGhlbHAzMlNuYXBzaG90"), D("UHJvY2VzczMyRmlyc3Q="), D("UHJvY2VzczMyTmV4dA==")),
            M(D("cHN1dGls")), S(D("dGFza2xpc3Q="), D("d21pYyBwcm9jZXNz"), D("Z2V0LXByb2Nlc3M="))))
         .Min(3),

        R("hidden-exec", "Hidden execution", "Defense evasion", Inf,
          D("SGlkZXMgd2luZG93cyBvciBmaWxlcyAoQ1JFQVRFX05PX1dJTkRPVywgU1dfSElERSwgYXR0cmliICtoKS4="),
          G(N(D("Q1JFQVRFX05PX1dJTkRPVw=="), D("U1dfSElERQ=="), D("U1RBUlRGX1VTRVNIT1dXSU5ET1c="), D("R2V0Q29uc29sZVdpbmRvdw==")),
            S(D("YXR0cmliICto"), D("YXR0cmliICtzICto"), D("YXR0cmliICtyICtzICto")))),

        R("self-delete", "Self-deletion", "Defense evasion", Sus,
          D("RGVsZXRlcyBpdHMgb3duIGZpbGUgYWZ0ZXIgZXhlY3V0aW9uIChwaW5nL3RpbWVvdXQgZm9sbG93ZWQgYnkgZGVsKS4="),
          G(S(D("cGluZyAxMjcuMC4wLjE="), D("cGluZyBsb2NhbGhvc3Q="), D("dGltZW91dCAvdA=="), D("Y2hvaWNlIC9jIHkgL24="))),
          G(S(D("ZGVsIC9m"), D("ZGVsIC9x"), D("ZGVsICI="), D("ZGVsICU="), D("cmVtb3ZlLWl0ZW0="))),
          G(N(D("X19maWxlX18="), D("YXJndg=="), D("ZXhlY3V0YWJsZQ=="), D("ZnJvemVu")))),

        R("log-clearing", "Event log clearing", "Defense evasion", Sus,
          D("Q2xlYXJzIFdpbmRvd3MgZXZlbnQgbG9ncyBvciB0aGUgVVNOIGpvdXJuYWwgdG8gZXJhc2UgdHJhY2VzLg=="),
          G(S(D("d2V2dHV0aWwgY2w="), D("d2V2dHV0aWwuZXhlIGNs"), D("Y2xlYXItZXZlbnRsb2c="), D("ZnN1dGlsIHVzbiBkZWxldGVqb3VybmFs")))),

        R("hosts-tamper", "Hosts file modification", "Defense evasion", Inf,
          D("UmVmZXJlbmNlcyB0aGUgaG9zdHMgZmlsZTsgc3VzcGljaW91cyB3aGVuIHNlY3VyaXR5IG9yIHVwZGF0ZSBkb21haW5zIGFyZSBwcmVzZW50IChibG9ja2luZyBBViB1cGRhdGVzKS4="),
          G(S(D("ZHJpdmVyc1xldGNcaG9zdHM="), D("L2V0Yy9ob3N0cw=="))))
         .Boost(Sus, G(S(D("dmlydXN0b3RhbC5jb20="), D("a2FzcGVyc2t5"), D("bWFsd2FyZWJ5dGVz"), D("Yml0ZGVmZW5kZXI="), D("YXZhc3Q="), D("d2luZG93c3VwZGF0ZS5taWNyb3NvZnQuY29t"),
                         D("dXBkYXRlLm1pY3Jvc29mdC5jb20="), D("bm9ydG9u"), D("bWNhZmVl")))),

        R("dll-loading", "DLL loading", "Native code", Inf,
          D("TG9hZHMgbmF0aXZlIGxpYnJhcmllcyAoY3R5cGVzIENETEwvV2luRExML3dpbmRsbCwgTG9hZExpYnJhcnkpIG9yIHJlc29sdmVzIGV4cG9ydGVkIGZ1bmN0aW9ucy4="),
          G(N(D("Q0RMTA=="), D("V2luRExM"), D("T2xlRExM"), D("UHlETEw="), D("d2luZGxs"), D("Y2RsbA=="), D("b2xlZGxs"), D("TG9hZExpYnJhcnk="), D("TG9hZExpYnJhcnlB"),
              D("TG9hZExpYnJhcnlX"), D("TG9hZExpYnJhcnlFeA=="), D("TG9hZExpYnJhcnlFeFc="), D("R2V0UHJvY0FkZHJlc3M=")),
            S(D("bG9hZGxpYnJhcnk=")))),

        R("raw-disk-access", "Raw disk access", "System", Sus,
          D("T3BlbnMgYSBwaHlzaWNhbCBkcml2ZSBkaXJlY3RseSAoTUJSL2Jvb3RraXQvd2lwZXIgYmVoYXZpb3VyLCBvciBkaXNrIHRvb2xpbmcpLg=="),
          G(S(D("XFwuXHBoeXNpY2FsZHJpdmU="), D("XFwuXHBoeWRydg==")))),

        R("mutex", "Mutex creation", "System", Inf,
          D("Q3JlYXRlcyBhIG11dGV4LCBhIGNvbW1vbiBzaW5nbGUtaW5zdGFuY2UgbWFya2VyIGluIG1hbHdhcmUu"),
          G(N(D("Q3JlYXRlTXV0ZXhX"), D("Q3JlYXRlTXV0ZXhB"), D("Q3JlYXRlTXV0ZXg=")))),

        R("process-discovery", "Process discovery / kill", "System", Inf,
          D("RW51bWVyYXRlcyBvciB0ZXJtaW5hdGVzIHByb2Nlc3NlcyAodGFza2xpc3QsIHRhc2traWxsLCBwcm9jZXNzX2l0ZXIsIFRvb2xoZWxwMzIpLg=="),
          G(N(D("cHJvY2Vzc19pdGVy"), D("RW51bVByb2Nlc3Nlcw=="), D("Q3JlYXRlVG9vbGhlbHAzMlNuYXBzaG90"), D("UHJvY2VzczMyRmlyc3Q="), D("UHJvY2VzczMyTmV4dA==")),
            S(D("dGFza2xpc3Q="), D("dGFza2tpbGw=")))),

        R("usb-spread", "USB / drive spreading", "System", Inf,
          D("RW51bWVyYXRlcyBkcml2ZXMgb3IgcmVmZXJlbmNlcyBhdXRvcnVuLmluZjsgc3VzcGljaW91cyB3aGVuIGJvdGggYXBwZWFyIChyZW1vdmFibGUtbWVkaWEgcHJvcGFnYXRpb24pLg=="),
          G(N(D("R2V0TG9naWNhbERyaXZlcw=="), D("R2V0RHJpdmVUeXBlVw=="), D("RFJJVkVfUkVNT1ZBQkxF"), D("ZGlza19wYXJ0aXRpb25z")), S(D("YXV0b3J1bi5pbmY="))))
         .Boost(Sus, G(N(D("R2V0TG9naWNhbERyaXZlcw=="), D("R2V0RHJpdmVUeXBlVw=="), D("RFJJVkVfUkVNT1ZBQkxF"), D("ZGlza19wYXJ0aXRpb25z"))), G(S(D("YXV0b3J1bi5pbmY=")))),

        // Exfiltration, C2, network
        R("discord-webhook", "Discord webhook", "Exfiltration / C2", Inf,
          D("VXNlcyBhIERpc2NvcmQgd2ViaG9vayBsaWJyYXJ5IG9yIFVSTDsgc3VzcGljaW91cyB3aGVuIGEgZnVsbCB3ZWJob29rIFVSTCAod2l0aCB0b2tlbikgaXMgaGFyZC1jb2RlZC4="),
          G(X(RxDiscordWebhook), S(D("ZGlzY29yZC5jb20vYXBpL3dlYmhvb2tz"), D("ZGlzY29yZGFwcC5jb20vYXBpL3dlYmhvb2tz")),
            M(D("ZGlzY29yZF93ZWJob29r"), D("ZGhvb2tz")), N(D("RGlzY29yZFdlYmhvb2s="), D("RGlzY29yZEVtYmVk"), D("U3luY1dlYmhvb2s="), D("QXN5bmNXZWJob29r"))))
         .Boost(Sus, G(X(RxDiscordWebhook))),

        R("discord-bot", "Discord bot", "Exfiltration / C2", Inf,
          D("VXNlcyBhIERpc2NvcmQgYm90IGxpYnJhcnk7IHN1c3BpY2lvdXMgd2hlbiBhIGJvdCB0b2tlbiBpcyBlbWJlZGRlZC4="),
          G(M(D("ZGlzY29yZA=="), D("ZGlzbmFrZQ=="), D("bmV4dGNvcmQ="), D("cHljb3Jk")), X(RxDiscordToken), X(RxDiscordMfa)))
         .Boost(Sus, G(X(RxDiscordToken), X(RxDiscordMfa))),

        R("telegram-bot", "Telegram bot", "Exfiltration / C2", Inf,
          D("VXNlcyBhIFRlbGVncmFtIGJvdCBsaWJyYXJ5IG9yIHRoZSBCb3QgQVBJOyBzdXNwaWNpb3VzIHdoZW4gYSBib3QgdG9rZW4gaXMgaGFyZC1jb2RlZC4="),
          G(M(D("dGVsZWJvdA=="), D("dGVsZWdyYW0="), D("YWlvZ3JhbQ=="), D("dGVsZXRob24="), D("cHlyb2dyYW0="), D("dGVsZXBvdA==")), X(RxTelegramToken),
            S(D("YXBpLnRlbGVncmFtLm9yZw=="))))
         .Boost(Sus, G(X(RxTelegramToken), S(D("YXBpLnRlbGVncmFtLm9yZy9ib3Q=")))),

        R("file-upload", "Uploads to file-sharing service", "Exfiltration / C2", Sus,
          D("UmVmZXJlbmNlcyBhIGZpbGUtaG9zdGluZyBvciBzaGFyaW5nIHNlcnZpY2Ugb2Z0ZW4gdXNlZCBmb3IgZXhmaWx0cmF0aW9uLg=="),
          G(S(D("cGFzdGViaW4uY29tL2FwaQ=="), D("cGFzdGUuZWU="), D("YW5vbmZpbGVz"), D("Z29maWxlLmlv"), D("dHJhbnNmZXIuc2g="), D("ZmlsZS5pby8="), D("Y2F0Ym94Lm1vZQ=="),
              D("YW5vbnltZmlsZQ=="), D("YmFzaHVwbG9hZA=="), D("dGVtcC5zaA=="), D("MHgwLnN0"), D("dWd1dS5zZQ=="), D("cGl4ZWxkcmFpbi5jb20vYXBp"), D("a3Jha2VuZmlsZXM=")))),

        R("remote-payload-host", "Payload hosting service", "Network", Sus,
          D("UmVmZXJlbmNlcyBhIHB1YmxpYyBwYXN0ZS9DRE4gaG9zdCBjb21tb25seSB1c2VkIHRvIHNlcnZlIHNlY29uZC1zdGFnZSBwYXlsb2FkcyBhbmQgcnVucyBvciB3cml0ZXMgd2hhdCBpdCBnZXRzLg=="),
          G(S(D("cGFzdGViaW4uY29tL3Jhdw=="), D("aGFzdGViaW4uY29tL3Jhdw=="), D("Z2lzdC5naXRodWJ1c2VyY29udGVudC5jb20="), D("cmF3LmdpdGh1YnVzZXJjb250ZW50LmNvbQ=="),
              D("cGFzdGUuZWUvcg=="), D("cmVudHJ5LmNv"), D("Z2hvc3RiaW4="), D("Y29udHJvbGMuY29t"), D("Y2RuLmRpc2NvcmRhcHAuY29tL2F0dGFjaG1lbnRz"), D("dHJhbnNmZXIuc2g="),
              D("Y2F0Ym94Lm1vZQ=="), D("YW5vbmZpbGVz"))),
          G(N(D("ZXhlYw=="), D("ZXZhbA=="), D("dXJsb3Blbg=="), D("dXJscmV0cmlldmU="), D("RG93bmxvYWRGaWxl"), D("UG9wZW4="), D("c3RhcnRmaWxl"), D("U2hlbGxFeGVjdXRl"), D("U2hlbGxFeGVjdXRlVw=="),
              D("Q3JlYXRlUHJvY2Vzcw=="), D("Q3JlYXRlUHJvY2Vzc1c=")), M(D("c3VicHJvY2Vzcw==")))),

        R("tunnel-ddns", "Tunnel / dynamic DNS", "Network", Sus,
          D("Q29ubmVjdHMgdG8gYSB0dW5uZWxsaW5nIG9yIGR5bmFtaWMtRE5TIHNlcnZpY2UgKG5ncm9rLCBEdWNrRE5TLCBOby1JUC4uLiksIHR5cGljYWwgZm9yIFJBVCBDMi4="),
          G(S(D("bmdyb2suaW8="), D("bmdyb2stZnJlZS5hcHA="), D("bmdyb2suYXBw"), D("c2VydmVvLm5ldA=="), D("dHJ5Y2xvdWRmbGFyZS5jb20="), D("ZHVja2Rucy5vcmc="), D("bm8taXAu"),
              D("ZGRucy5uZXQ="), D("aG9wdG8ub3Jn"), D("emFwdG8ub3Jn"), D("c2VydmViZWVyLmNvbQ=="), D("c3l0ZXMubmV0"), D("bXlmdHAuYml6"), D("cG9ydG1hcC5pbw=="), D("cGxheWl0Lmdn"),
              D("bG9jYWx0b25ldC5jb20="), D("bG9jYS5sdA=="), D("bG9jYWxob3N0LnJ1bg=="), D("cGFnZWtpdGUubWU="), D("Ym9yZS5wdWI="))),
          G(M(NetLibs))),

        R("raw-ip-url", "URL with raw IP address", "Network", Sus,
          D("Q29udGFjdHMgYSBwdWJsaWMgSVAgYWRkcmVzcyBkaXJlY3RseSBpbnN0ZWFkIG9mIGEgZG9tYWluIG5hbWUgKGNvbW1vbiBmb3IgQzIgYW5kIHBheWxvYWQgc2VydmVycyku"),
          G(X(RxRawIpUrl))),

        R("reverse-shell", "Reverse / bind shell", "Exfiltration / C2", Mal,
          D("Q29ubmVjdHMgKG9yIGxpc3RlbnMpIG9uIGEgc29ja2V0IGFuZCB3aXJlcyBpdCB0byBhIGNvbW1hbmQgaW50ZXJwcmV0ZXIu"),
          G(M(D("c29ja2V0"))),
          G(N(D("Y29ubmVjdA=="), D("Y3JlYXRlX2Nvbm5lY3Rpb24="), D("YWNjZXB0"))),
          G(N(D("ZHVwMg=="), D("UG9wZW4="), D("cHR5"), D("c3Bhd24="), D("UElQRQ=="), D("U1RET1VU"), D("c3RhcnRmaWxl"), D("c3lzdGVt"), D("ZmlsZW5v"))),
          G(S(D("Y21kLmV4ZQ=="), D("L2Jpbi9zaA=="), D("L2Jpbi9iYXNo"), D("L2Jpbi96c2g="), D("L2Jpbi9hc2g="), D("L2Jpbi9kYXNo"), D("cG93ZXJzaGVsbA=="), D("c2ggLWk="), D("YmFzaCAtaQ=="))))
         .Near(),

        R("ip-lookup", "External IP lookup", "Recon", Inf,
          D("UXVlcmllcyBhIHNlcnZpY2UgZm9yIHRoZSBwdWJsaWMgSVAgYWRkcmVzcyBvciBnZW9sb2NhdGlvbi4="),
          G(S(D("YXBpLmlwaWZ5Lm9yZw=="), D("aXBpbmZvLmlv"), D("aXAtYXBpLmNvbQ=="), D("aWZjb25maWcubWU="), D("aWNhbmhhemlw"), D("Y2hlY2tpcC5hbWF6b25hd3M="), D("aXBhcGkuY28="),
              D("bXlleHRlcm5hbGlw"), D("d3RmaXNteWlw"), D("aWRlbnQubWU="), D("YXBpLm15aXAuY29t"), D("Z2VvbG9jYXRpb24tZGIuY29t")))),

        R("downloader", "File download", "Network", Inf,
          D("RG93bmxvYWRzIGZpbGVzICh1cmxyZXRyaWV2ZSwgVVJMRG93bmxvYWRUb0ZpbGUsIGNlcnR1dGlsIC11cmxjYWNoZS4uLik7IHN1c3BpY2lvdXMgd2hlbiBhbiBleGVjdXRhYmxlL3NjcmlwdCBuYW1lIGlzIGludm9sdmVkLg=="),
          G(N(D("dXJscmV0cmlldmU="), D("VVJMRG93bmxvYWRUb0ZpbGU="), D("VVJMRG93bmxvYWRUb0ZpbGVX"), D("VVJMRG93bmxvYWRUb0ZpbGVB"), D("RG93bmxvYWRGaWxl"),
              D("SW50ZXJuZXRPcGVuVXJsVw=="), D("SW50ZXJuZXRSZWFkRmlsZQ==")),
            S(D("ZG93bmxvYWRmaWxl"), D("Yml0c2FkbWluIC90cmFuc2Zlcg=="), D("Y2VydHV0aWwgLXVybGNhY2hl"), D("Y3VybCAtbw=="), D("d2dldCA="))))
         .Boost(Sus, G(S(D("LmV4ZQ=="), D("LmRsbA=="), D("LmJhdA=="), D("LnBzMQ=="), D("LnZicw=="), D("LnNjcg=="), D("Lm1zaQ=="), D("Lmh0YQ=="), D("LmNtZA=="), D("Lmxuaw==")))),

        R("network", "Network communication", "Network", Inf,
          D("T3BlbnMgc29ja2V0cyBvciBIVFRQLCBGVFAsIFNNVFAsIG9yIFNTSCBjb25uZWN0aW9ucy4="),
          G(M(NetLibs))),

        R("tor-proxy", "Tor / proxy", "Network", Inf,
          D("UmVmZXJlbmNlcyBUb3IgKC5vbmlvbikgb3IgU09DS1MgcHJveGllczsgc3VzcGljaW91cyB3aGVuIGNvbWJpbmVkIHdpdGggbmV0d29yayBjb2RlLg=="),
          G(S(D("Lm9uaW9u"), D("c29ja3M1Oi8v"), D("c29ja3M1aDovLw=="), D("dG9ycmM="), D("dG9yLmV4ZQ=="), D("MTI3LjAuMC4xOjkwNTA="), D("MTI3LjAuMC4xOjkxNTA=")),
            M(D("c29ja3M="), D("c3RlbS5jb250cm9s"), D("c3RlbS5wcm9jZXNz"))))
         .Boost(Sus, G(S(D("Lm9uaW9u"))), G(M(NetLibs))),

        R("ddos-tool", "DDoS tooling", "Impact", Sus,
          D("UmVmZXJlbmNlcyBmbG9vZCBhdHRhY2tzIGFuZCBvcGVucyBuZXR3b3JrIGNvbm5lY3Rpb25zLg=="),
          G(S(D("c3luIGZsb29k"), D("dWRwIGZsb29k"), D("aHR0cCBmbG9vZA=="), D("aWNtcCBmbG9vZA=="), D("c2xvd2xvcmlz"), D("ZGRvcyBhdHRhY2s="))),
          G(M(NetLibs))),

        // Data theft and surveillance
        R("stealer", "Credential / browser data theft", "Stealer", Sus,
          D("UmVhZHMgYnJvd3NlciBwcm9maWxlcyAoTG9naW4gRGF0YSwgY29va2llcywgTG9jYWwgU3RhdGUpIGFuZCBkZWNyeXB0cyBvciBxdWVyaWVzIHNlY3JldHMu"),
          G(S(D("bG9naW4gZGF0YQ=="), D("bG9naW5zLmpzb24="), D("a2V5NC5kYg=="), D("Y29va2llcy5zcWxpdGU="), D("dXNlciBkYXRhXGRlZmF1bHQ="), D("dXNlciBkYXRhXHByb2ZpbGU="),
              D("XGxvY2FsIHN0YXRl"), D("XG5ldHdvcmtcY29va2llcw=="), D("d2ViIGRhdGE="), D("Y3JlZGl0X2NhcmRz"), D("c2lnbm9ucy5zcWxpdGU="), D("bW96X2xvZ2lucw=="),
              D("bW96X2Nvb2tpZXM="), D("cGFzc3dvcmRfdmFsdWU="), D("ZW5jcnlwdGVkX2tleQ=="), D("b3NfY3J5cHQ="), D("ZW5jcnlwdGVkX3ZhbHVl"))),
          G(N(D("Q3J5cHRVbnByb3RlY3REYXRh"), D("Z2V0X2VuY3J5cHRpb25fa2V5"), D("ZGVjcnlwdF9wYXNzd29yZA=="), D("ZGVjcnlwdF9jaHJvbWU="), D("Z2V0X21hc3Rlcl9rZXk="), D("QUVTR0NN")),
            M(D("c3FsaXRlMw=="), D("d2luMzJjcnlwdA=="))))
         .Boost(Mal, G(S(D("cGFzc3dvcmRfdmFsdWU="), D("ZW5jcnlwdGVkX2tleQ=="), D("b3NfY3J5cHQ="), D("ZW5jcnlwdGVkX3ZhbHVl"), D("bG9naW5zLmpzb24="), D("a2V5NC5kYg=="),
                         D("c2lnbm9ucy5zcWxpdGU="), D("bW96X2xvZ2lucw=="), D("bW96X2Nvb2tpZXM=")))),

        R("discord-token-theft", "Discord token theft", "Stealer", Mal,
          D("TG9va3MgZm9yIERpc2NvcmQgdG9rZW5zIGluIGxvY2FsIHN0b3JhZ2UgKGxldmVsZGIpIG9yIHZhbGlkYXRlcyB0b2tlbnMgdmlhIC91c2Vycy9AbWUu"),
          G(S(D("bG9jYWwgc3RvcmFnZVxsZXZlbGRi"), D("ZHF3NHc5d2d4Y3E6"), D("ZGlzY29yZGNhbmFyeQ=="), D("ZGlzY29yZHB0Yg=="), D("ZGlzY29yZGRldmVsb3BtZW50"))),
          G(S(D("ZGlzY29yZA=="), D("L3VzZXJzL0BtZQ==")), X(RxDiscordToken), X(RxDiscordMfa))),

        R("crypto-wallet", "Crypto wallet targeting", "Stealer", Sus,
          D("VGFyZ2V0cyBjcnlwdG9jdXJyZW5jeSB3YWxsZXQgZmlsZXMgb3Igd2FsbGV0IGJyb3dzZXIgZXh0ZW5zaW9ucy4="),
          G(S(D("d2FsbGV0LmRhdA=="), D("ZXhvZHVzLndhbGxldA=="), D("ZWxlY3RydW1cd2FsbGV0cw=="), D("YXRvbWljXGxvY2FsIHN0b3JhZ2U="), D("Y29pbm9taVxjb2lub21pXHdhbGxldHM="),
              D("XGV0aGVyZXVtXGtleXN0b3Jl"), D("d2FzYWJpd2FsbGV0"), D("bW9uZXJvLXdhbGxldA=="), D("bWV0YW1hc2s="),
              D("bmtiaWhmYmVvZ2FlYW9laGxlZm5rb2RiZWZncGdrbm4="), D("ZWpiYWxiYWtvcGxjaGxnaGVjZGFsbWVlZWFqbmltaG0="), D("YmZuYWVsbW9tZWltaGxwbWdqbmpvcGhocGtrb2xqcGE="),
              D("aWJuZWpkZmptbWtwY25scGVia2xtbmtvZW9paG9mZWM="), D("Zmhib2hpbWFlbGJvaHBqYmJsZGNuZ2NuYXBuZG9kanA="), D("aG5mYW5rbm9jZmVvZmJkZGdjaWpubWhuZm5rZG5hYWQ="),
              D("YWhvbHBmZGlhbGpnamZob21paGtqYm1namlkbGNkbm8="), D("ZG1rYW1ja25vZ2tnY2RmaGhiZGRjZ2hhY2hrZWplYXA="), D("ZmZuYmVsZmRvZWlvaGVua2ppYm5tYWRqaWVoamhhamI="),
              D("YWVhY2hrbm1lZnBoZXBjY2lvbmJvb2hja29ub2VlbWc=")))),

        R("app-credential-theft", "Application credential theft", "Stealer", Sus,
          D("UmVhZHMgU1NIIGtleXMsIGNsb3VkL0dpdCBjcmVkZW50aWFscywgRlRQIGNsaWVudCBzdG9yZXMsIFRlbGVncmFtIHNlc3Npb25zIG9yIGdhbWUgbGF1bmNoZXIgY3JlZGVudGlhbHMu"),
          G(S(D("ZmlsZXppbGxhXHJlY2VudHNlcnZlcnMueG1s"), D("c2l0ZW1hbmFnZXIueG1s"), D("LnNzaC9pZF9yc2E="), D("LnNzaFxpZF9yc2E="), D("aWRfZWQyNTUxOQ=="),
              D("LmF3cy9jcmVkZW50aWFscw=="), D("LmF3c1xjcmVkZW50aWFscw=="), D("LmdpdC1jcmVkZW50aWFscw=="), D("bG9naW51c2Vycy52ZGY="), D("c3Nmbg=="), D("LnJvYmxvc2VjdXJpdHk="),
              D("bGF1bmNoZXJfcHJvZmlsZXMuanNvbg=="), D("bGF1bmNoZXJfYWNjb3VudHMuanNvbg=="), D("dGVsZWdyYW0gZGVza3RvcFx0ZGF0YQ==")),
            X(D("KD9pKVxidGRhdGFcYg==")))),

        R("wifi-dump", "Wi-Fi password dump", "Stealer", Sus,
          D("RXh0cmFjdHMgc2F2ZWQgV2ktRmkgcGFzc3dvcmRzIChuZXRzaCB3bGFuIHNob3cgcHJvZmlsZSBrZXk9Y2xlYXIpLg=="),
          G(S(D("bmV0c2ggd2xhbiBzaG93IHByb2ZpbGU="), D("d2xhbiBzaG93IHByb2ZpbGVz"), D("a2V5PWNsZWFy")))),

        R("credential-dumping", "Credential dumping tools", "Credential access", Sus,
          D("UmVmZXJlbmNlcyBMU0FTUyBkdW1waW5nIG9yIHdlbGwta25vd24gY3JlZGVudGlhbC9BRCBhdHRhY2sgdG9vbHMu"),
          G(S(D("bHNhc3M="), D("bWltaWthdHo="), D("c2VrdXJsc2E="), D("bGF6YWduZQ=="), D("bnRkcy5kaXQ="), D("Y29tc3Zjcy5kbGw="), D("cmVnIHNhdmUgaGtsbVxzYW0="), D("c2VjcmV0c2R1bXA="),
              D("a2VyYmVyb2FzdA=="), D("cnViZXVz"), D("c2hhcnBob3VuZA=="), D("Y3JhY2ttYXBleGVj"), D("aW52b2tlLW1pbWlrYXR6"), D("cHNleGVj"), D("d2NlLmV4ZQ=="), D("cHJvY2R1bXA="))))
         .Boost(Mal, G(S(D("bWltaWthdHo="), D("c2VrdXJsc2E="), D("bGF6YWduZQ=="), D("bnRkcy5kaXQ="), D("c2VjcmV0c2R1bXA="), D("a2VyYmVyb2FzdA=="), D("cnViZXVz"),
                         D("c2hhcnBob3VuZA=="), D("Y3JhY2ttYXBleGVj"), D("aW52b2tlLW1pbWlrYXR6")))),

        R("keylogger", "Keylogger", "Spyware", Sus,
          D("SG9va3MgdGhlIGtleWJvYXJkIChweW5wdXQva2V5Ym9hcmQgbGlzdGVuZXJzLCBTZXRXaW5kb3dzSG9va0V4KSB0byBjYXB0dXJlIGtleXN0cm9rZXMu"),
          G(M(D("cHlucHV0"), D("a2V5Ym9hcmQ="), D("cHl4aG9vaw=="), D("cHlob29r")),
            N(D("U2V0V2luZG93c0hvb2tFeA=="), D("U2V0V2luZG93c0hvb2tFeEE="), D("U2V0V2luZG93c0hvb2tFeFc="))),
          G(N(D("b25fcHJlc3M="), D("b25fcmVsZWFzZQ=="), D("TGlzdGVuZXI="), D("aG9vaw=="), D("aG9va19rZXk="), D("cmVhZF9ldmVudA=="), D("cmVjb3Jk"), D("b25fa2V5X3ByZXNz"),
              D("S2V5Ym9hcmRFdmVudA=="), D("SG9va01hbmFnZXI="), D("SG9va0tleWJvYXJk"), D("U2V0V2luZG93c0hvb2tFeA=="), D("U2V0V2luZG93c0hvb2tFeEE="), D("U2V0V2luZG93c0hvb2tFeFc=")))),

        R("key-polling", "Key-state polling", "Spyware", Inf,
          D("UG9sbHMgR2V0QXN5bmNLZXlTdGF0ZTsgc3VzcGljaW91cyB3aGVuIHNwZWNpYWwta2V5IGxhYmVscyBhcmUgbWFwcGVkICh0eXBpY2FsIHNjcmlwdCBrZXlsb2dnZXIpLg=="),
          G(N(D("R2V0QXN5bmNLZXlTdGF0ZQ=="), D("R2V0S2V5Ym9hcmRTdGF0ZQ=="))))
         .Boost(Sus, G(S(D("W2VudGVyXQ=="), D("W2JhY2tzcGFjZV0="), D("W3NwYWNlXQ=="), D("W3RhYl0="), D("W3NoaWZ0XQ=="), D("W2N0cmxd"), D("W2NhcHNd"), D("PGVudGVyPg=="), D("PGJhY2tzcGFjZT4=")))),

        R("screenshot", "Screen capture", "Spyware", Inf,
          D("Q2FwdHVyZXMgdGhlIHNjcmVlbiAoSW1hZ2VHcmFiLCBweWF1dG9ndWkuc2NyZWVuc2hvdCwgbXNzLCBCaXRCbHQpLg=="),
          G(M(D("UElMLkltYWdlR3JhYg=="), D("bXNz"), D("cHlzY3JlZW5zaG90")), N(D("SW1hZ2VHcmFi"), D("c2NyZWVuc2hvdA=="), D("Qml0Qmx0")))),

        R("clipboard", "Clipboard access", "Spyware", Inf,
          D("UmVhZHMgZnJvbSBvciBtb2RpZmllcyB0aGUgY2xpcGJvYXJkLg=="),
          G(M(D("cHlwZXJjbGlw"), D("d2luMzJjbGlwYm9hcmQ="), D("Y2xpcGJvYXJk")),
            N(D("R2V0Q2xpcGJvYXJkRGF0YQ=="), D("T3BlbkNsaXBib2FyZA=="), D("U2V0Q2xpcGJvYXJkRGF0YQ=="), D("Y2xpcGJvYXJkX2dldA=="), D("Y2xpcGJvYXJkX2FwcGVuZA==")))),

        R("clipper", "Crypto clipper", "Theft", Sus,
          D("QWNjZXNzZXMgdGhlIGNsaXBib2FyZCBhbmQgY29udGFpbnMgY3J5cHRvY3VycmVuY3kgYWRkcmVzcyBwYXR0ZXJucyAoYWRkcmVzcyBzd2FwcGluZyku"),
          G(M(D("cHlwZXJjbGlw"), D("d2luMzJjbGlwYm9hcmQ="), D("Y2xpcGJvYXJk")),
            N(D("R2V0Q2xpcGJvYXJkRGF0YQ=="), D("T3BlbkNsaXBib2FyZA=="), D("U2V0Q2xpcGJvYXJkRGF0YQ=="), D("Y2xpcGJvYXJkX2dldA=="), D("Y2xpcGJvYXJkX2FwcGVuZA=="))),
          G(X(RxCryptoAddr)))
         .Boost(Mal, G(N(D("Y29weQ=="), D("U2V0Q2xpcGJvYXJkRGF0YQ=="), D("Y2xpcGJvYXJkX2FwcGVuZA=="), D("RW1wdHlDbGlwYm9hcmQ="))),
                     G(N(D("cGFzdGU="), D("R2V0Q2xpcGJvYXJkRGF0YQ=="), D("Y2xpcGJvYXJkX2dldA=="), D("T3BlbkNsaXBib2FyZA=="))), G(N(D("c2xlZXA=")))),

        R("webcam-mic", "Webcam / microphone", "Spyware", Inf,
          D("QWNjZXNzZXMgdGhlIHdlYmNhbSBvciBtaWNyb3Bob25lLg=="),
          G(N(D("VmlkZW9DYXB0dXJl"), D("Y2FwQ3JlYXRlQ2FwdHVyZVdpbmRvdw=="), D("Y2FwR2V0RHJpdmVyRGVzY3JpcHRpb24="), D("UHlBdWRpbw==")), M(D("cHlhdWRpbw==")))),

        R("sysinfo", "System information gathering", "Recon", Inf,
          D("Q29sbGVjdHMgc3lzdGVtIGluZm9ybWF0aW9uIChXTUksIHN5c3RlbWluZm8sIHN0b3JhZ2UsIG1lbW9yeSwgb3IgaGFyZHdhcmUgZGV0YWlscyku"),
          G(S(D("c3lzdGVtaW5mbw=="), D("d2luMzJfY29tcHV0ZXJzeXN0ZW1wcm9kdWN0"), D("d2luMzJfcHJvY2Vzc29y"), D("d2luMzJfdmlkZW9jb250cm9sbGVy"), D("d2luMzJfYmlvcw=="),
              D("c2VsZWN0ICogZnJvbSB3aW4zMl8="), D("bnZpZGlhLXNtaQ==")),
            M(D("d21p")), N(D("R2V0Vm9sdW1lSW5mb3JtYXRpb25X"), D("R2xvYmFsTWVtb3J5U3RhdHVzRXg=")))),

        // Impact
        R("ransomware", "Possible ransomware behaviour", "Impact", Mal,
          D("Q29tYmluZXMgZW5jcnlwdGlvbiwgZmlsZSB0cmF2ZXJzYWwgYW5kIGV4cGxpY2l0IHJhbnNvbS1ub3RlIHdvcmRpbmcu"),
          G(M(CryptoLibs), N(D("RmVybmV0"), D("QUVT"), D("ZW5jcnlwdA=="), D("ZW5jcnlwdF9maWxl"), D("RW5jcnlwdEZpbGU="))),
          G(N(WalkNames)),
          G(X(RxRansomText))),

        R("file-encryptor", "Mass file encryptor", "Impact", Sus,
          D("RW5jcnlwdHMgZmlsZXMgd2hpbGUgd2Fsa2luZyBkaXJlY3RvcmllcyBhbmQgcmVuYW1lcyB0aGVtIHRvIGEgcmFuc29td2FyZS1zdHlsZSBleHRlbnNpb24u"),
          G(M(CryptoLibs), N(D("RmVybmV0"), D("QUVT"), D("ZW5jcnlwdA=="), D("ZW5jcnlwdF9maWxl"), D("RW5jcnlwdEZpbGU="))),
          G(N(WalkNames)),
          G(N(D("cmVuYW1l"), D("cmVwbGFjZQ=="), D("cmVtb3Zl"), D("dW5saW5r"))),
          G(X(RxRansomExt))),

        R("backup-destruction", "Backup / recovery destruction", "Impact", Mal,
          D("RGVsZXRlcyBzaGFkb3cgY29waWVzIG9yIHJlY292ZXJ5IG9wdGlvbnMgKHR5cGljYWwgcmFuc29td2FyZSBwcmVwYXJhdGlvbiku"),
          G(S(D("dnNzYWRtaW4gZGVsZXRlIHNoYWRvd3M="), D("dnNzYWRtaW4uZXhlIGRlbGV0ZSBzaGFkb3dz"), D("c2hhZG93Y29weSBkZWxldGU="), D("d2JhZG1pbiBkZWxldGUgY2F0YWxvZw=="),
              D("cmVjb3ZlcnllbmFibGVkIG5v"), D("Ym9vdHN0YXR1c3BvbGljeSBpZ25vcmVhbGxmYWlsdXJlcw=="), D("Y2lwaGVyIC93"), D("ZGVsZXRlIHNoYWRvd3M=")))),

        R("miner", "Crypto miner", "Impact", Sus,
          D("UmVmZXJlbmNlcyBtaW5pbmcgcG9vbHMgb3IgbWluZXIgc29mdHdhcmUu"),
          G(S(D("c3RyYXR1bSt0Y3A="), D("c3RyYXR1bStzc2w="), D("c3RyYXR1bTIrdGNw"), D("eG1yaWc="), D("bWluZXJnYXRl"), D("bmljZWhhc2g="), D("cG9vbC5zdXBwb3J0eG1y"),
              D("bW9uZXJvb2NlYW4="), D("bmFub3Bvb2wub3Jn"), D("Mm1pbmVycy5jb20="), D("aGFzaHZhdWx0LnBybw=="), D("dW5taW5lYWJsZQ=="), D("Y3J5cHRvbmlnaHQ="), D("cmFuZG9teA=="),
              D("ZG9uYXRlLWxldmVs"), D("Y3B1bWluZXI="), D("Y2NtaW5lcg=="), D("bmJtaW5lcg=="), D("bG9sbWluZXI="), D("cGhvZW5peG1pbmVy"), D("eG1yLXN0YWs="))))
         .Boost(Mal, G(S(D("c3RyYXR1bSt0Y3A="), D("c3RyYXR1bStzc2w="), D("c3RyYXR1bTIrdGNw"), D("eG1yaWc="), D("ZG9uYXRlLWxldmVs"), D("eG1yLXN0YWs="), D("Y3B1bWluZXI="),
                         D("Y2NtaW5lcg=="), D("bmJtaW5lcg=="), D("bG9sbWluZXI="), D("cGhvZW5peG1pbmVy")))),
    };

    // Correlation chains

    static MetaGroup Gp(int min, FlagSeverity minSev, params string[] ids) =>
        new MetaGroup { Ids = ids, Min = min, MinSev = minSev };

    static Meta Mt(string id, string label, FlagSeverity sev, string desc, params MetaGroup[] req) =>
        new Meta { Id = id, Label = label, Sev = sev, Desc = desc, Req = req };

    static readonly string[] Theft =
        { "stealer", "discord-token-theft", "crypto-wallet", "app-credential-theft", "wifi-dump", "keylogger", "clipper", "credential-dumping" };
    static readonly string[] Exfil = { "discord-webhook", "telegram-bot", "discord-bot", "file-upload" };
    static readonly string[] WeakCollect = { "screenshot", "webcam-mic", "clipboard", "sysinfo", "ip-lookup", "process-discovery" };
    static readonly string[] BotCaps =
        { "shell-exec", "os-system", "screenshot", "webcam-mic", "keylogger", "clipboard", "process-discovery", "sysinfo", "file-upload", "ip-lookup", "downloader" };
    static readonly string[] Loaders = { "loader", "marshal-loader", "remote-exec" };
    static readonly string[] Obfus =
        { "opaque-blob", "packed", "pyarmor", "string-obfuscation", "builtins-access", "codec-obfuscation", "hidden-code-object" };
    static readonly string[] Evasion = { "anti-vm", "anti-analysis-tools", "security-product-kill", "anti-debug" };
    static readonly string[] Payload =
        { "loader", "marshal-loader", "remote-exec", "injection", "shellcode", "stealer", "keylogger", "downloader", "hidden-code-object", "embedded-exe" };

    static readonly List<Meta> Metas = BuildMetas();

    static List<Meta> BuildMetas() => new()
    {
        Mt("chain-theft-exfil", "Data theft with exfiltration channel", Mal,
           D("QSB0aGVmdCBjYXBhYmlsaXR5IChicm93c2VyL2NyZWRlbnRpYWxzL3dhbGxldC9rZXlsb2dnZXIvV2ktRmkpIGlzIGNvbWJpbmVkIHdpdGggYSBEaXNjb3JkL1RlbGVncmFtL2ZpbGUtc2hhcmluZyBleGZpbHRyYXRpb24gY2hhbm5lbC4="),
           Gp(1, Sus, Theft), Gp(1, Inf, Exfil)),

        Mt("chain-collect-exfil", "Data collection with exfiltration channel", Sus,
           D("U2V2ZXJhbCBjb2xsZWN0aW9uIGJlaGF2aW91cnMgKHNjcmVlbnNob3RzLCBjbGlwYm9hcmQsIHN5c3RlbSBpbmZvLCBJUCBsb29rdXAuLi4pIHBsdXMgYSBjb25jcmV0ZSBleGZpbHRyYXRpb24gY2hhbm5lbC4="),
           Gp(2, Inf, WeakCollect), Gp(1, Sus, Exfil)),

        Mt("chain-bot-rat", "Chat-bot remote access", Sus,
           D("QSBEaXNjb3JkL1RlbGVncmFtIGJvdCBsaWJyYXJ5IGNvbWJpbmVkIHdpdGggcmVtb3RlLWNvbnRyb2wgY2FwYWJpbGl0aWVzIChzaGVsbCwgc2NyZWVuc2hvdHMsIGtleWxvZ2dpbmcsIGZpbGUgdXBsb2FkLi4uKS4="),
           Gp(1, Inf, "discord-bot", "telegram-bot"), Gp(2, Inf, BotCaps))
          .Up(Mal, Gp(4, Inf, BotCaps)),

        Mt("chain-obfuscated-loader", "Obfuscated loader", Sus,
           D("QSBkZWNvZGUvZG93bmxvYWQtYW5kLWV4ZWN1dGUgbG9hZGVyIHRoYXQgaXMgYWxzbyBoaWRkZW4gYnkgb2JmdXNjYXRpb24gb3IgcGFja2luZy4="),
           Gp(1, Sus, Loaders), Gp(1, Inf, Obfus))
          .Up(Mal, Gp(1, Mal, Loaders)),

        Mt("chain-dropper", "Downloader that executes what it fetches", Sus,
           D("RG93bmxvYWRzIG9yIGZldGNoZXMgYSBwYXlsb2FkIGFuZCBydW5zIGl0OyBlc2NhbGF0ZXMgd2hlbiBldmFzaW9uIG9yIHBlcnNpc3RlbmNlIGlzIGFsc28gcHJlc2VudC4="),
           Gp(1, Sus, "downloader", "remote-payload-host"), Gp(1, Inf, "shell-exec", "os-system", "loader", "embedded-exe", "remote-exec"))
          .Up(Mal, Gp(1, Inf, "hidden-exec", "persistence", "defender-tamper", "defender-exclusion", "anti-vm", "anti-analysis-tools", "uac-bypass")),

        Mt("chain-persistent-agent", "Persistent network agent", Sus,
           D("SW5zdGFsbHMgcGVyc2lzdGVuY2UsIHRhbGtzIHRvIHRoZSBuZXR3b3JrIGFuZCBydW5zIGNvbW1hbmRzIG9yIHNwaWVzOyBlc2NhbGF0ZXMgd2l0aCBzdGVhbHRoIG9yIHByaXZpbGVnZSB0YW1wZXJpbmcu"),
           Gp(1, Sus, "persistence"),
           Gp(1, Inf, "network", "tor-proxy", "discord-bot", "telegram-bot", "discord-webhook", "tunnel-ddns"),
           Gp(1, Inf, "hidden-exec", "shell-exec", "os-system", "keylogger", "screenshot", "stealer"))
          .Up(Mal, Gp(1, Inf, "hidden-exec", "defender-tamper", "defender-exclusion", "uac-bypass", "anti-vm", "anti-analysis-tools")),

        Mt("chain-evasion-payload", "Evasion combined with a payload", Mal,
           D("QW50aS1WTS9hbnRpLWFuYWx5c2lzL0FWLWtpbGxpbmcgYmVoYXZpb3VyIHRvZ2V0aGVyIHdpdGggYSBsb2FkZXIsIGluamVjdG9yLCBzdGVhbGVyIG9yIGRyb3BwZXIu"),
           Gp(1, Sus, Evasion), Gp(1, Sus, Payload)),

        Mt("chain-cred-dump-exfil", "Credential dumping with exfiltration", Mal,
           D("Q3JlZGVudGlhbC1kdW1waW5nIHRvb2xpbmcgY29tYmluZWQgd2l0aCBhbiBleGZpbHRyYXRpb24gY2hhbm5lbC4="),
           Gp(1, Inf, "credential-dumping"), Gp(1, Inf, Exfil)),

        Mt("chain-ransom-prep", "Ransomware preparation", Mal,
           D("TWFzcyBmaWxlIGVuY3J5cHRpb24gdG9nZXRoZXIgd2l0aCBiYWNrdXAgZGVzdHJ1Y3Rpb24gb3IgbG9nIGNsZWFyaW5nLg=="),
           Gp(1, Inf, "file-encryptor"), Gp(1, Inf, "backup-destruction", "log-clearing", "security-product-kill")),
    };

    // Evaluation

    static List<FlagEvidence> CollectGroup(Sig[] g, Corpus k)
    {
        var ev = new List<FlagEvidence>();
        var seen = new HashSet<object>();
        foreach (var s in g) Collect(s, k, ev, seen);
        return ev;
    }

    static void Collect(Sig s, Corpus k, List<FlagEvidence> ev, HashSet<object> seen)
    {
        switch (s.K)
        {
            case 'M':
                foreach (var m in k.Modules)
                {
                    if (ev.Count >= MaxCollect) return;
                    bool hit = false;
                    foreach (var key in m.Keys)
                    {
                        foreach (var a in s.Subs)
                            if (key == a || key.StartsWith(a + ".", StringComparison.Ordinal)) { hit = true; break; }
                        if (hit) break;
                    }
                    if (hit && seen.Add(m)) ev.Add(new FlagEvidence { Kind = "import", Text = m.Text, Code = m.Code, Src = m });
                }
                break;

            case 'N':
                foreach (var a in s.Subs)
                    if (k.Names.TryGetValue(a, out var list))
                        foreach (var it in list)
                        {
                            if (ev.Count >= MaxCollect) return;
                            if (seen.Add(it)) ev.Add(new FlagEvidence { Kind = "name", Text = it.Text, Code = it.Code, Src = it });
                        }
                break;

            case 'S':
                foreach (var it in k.Strings)
                {
                    if (ev.Count >= MaxCollect) return;
                    foreach (var a in s.Subs)
                    {
                        int i = it.Lower.IndexOf(a, StringComparison.Ordinal);
                        if (i < 0) continue;
                        if (seen.Add(it)) ev.Add(new FlagEvidence { Kind = it.Kind, Text = Snip(it.Text, i, a.Length), Code = it.Code, Src = it });
                        break;
                    }
                }
                break;

            case 'X':
                foreach (var it in k.Strings)
                {
                    if (ev.Count >= MaxCollect) return;
                    try
                    {
                        var m = s.Rx.Match(it.Text);
                        if (m.Success && seen.Add(it))
                            ev.Add(new FlagEvidence { Kind = it.Kind, Text = Short(m.Value, 120), Code = it.Code, Src = it });
                    }
                    catch (RegexMatchTimeoutException) { }
                }
                break;

            case 'E':
                foreach (var it in k.Blobs)
                {
                    if (ev.Count >= MaxCollect) return;
                    if (seen.Add(it)) ev.Add(new FlagEvidence { Kind = "blob", Text = it.Text, Code = it.Code, Src = it });
                }
                break;
        }
    }

    static EvalResult Eval(Rule r, Corpus k)
    {
        var res = new EvalResult();
        var mseen = new HashSet<object>();
        var perGroup = new List<List<FlagEvidence>>();

        foreach (var g in r.Groups)
        {
            var ev = CollectGroup(g, k);
            if (ev.Count == 0) return null;                  // An AND group had no matches.
            perGroup.Add(ev);
        }
        if (perGroup.Count > 0 && perGroup[0].Count < r.MinEv) return null;

        if (r.BoostGroups != null)
        {
            var extra = new List<List<FlagEvidence>>();
            bool ok = true;
            foreach (var g in r.BoostGroups)
            {
                var ev = CollectGroup(g, k);
                if (ev.Count == 0) { ok = false; break; }
                extra.Add(ev);
            }
            if (ok) { res.Boosted = true; perGroup.AddRange(extra); }
        }

        foreach (var ev in perGroup)
            foreach (var e in ev)
                if (mseen.Add(e.Src)) res.Ev.Add(e);

        if (r.IsNear && perGroup.Count > 1) res.Scattered = !Colocated(perGroup);
        return res;
    }

    // True when at least one code object holds evidence for every non-import group. Imports are file-level, so they are skipped.
    static bool Colocated(List<List<FlagEvidence>> groups)
    {
        HashSet<PyCode> common = null;
        foreach (var g in groups)
        {
            if (g.All(e => e.Kind == "import")) continue;
            var codes = new HashSet<PyCode>(g.Where(e => e.Kind != "import" && e.Code != null).Select(e => e.Code));
            if (common == null) common = codes; else common.IntersectWith(codes);
            if (common.Count == 0) return false;
        }
        return true;
    }

    static int Conf(FlagSeverity sev, EvalResult e, Rule r)
    {
        int c = sev == Mal ? 65 : sev == Sus ? 55 : 45;
        if (e.Boosted) c += 15;
        if (r.IsNear) c += e.Scattered ? -15 : 10;
        if (e.Ev.Any(x => x.Kind == "decoded")) c += 10;           // hidden behind encoding: deliberate
        if (e.Ev.Select(x => x.Kind).Distinct().Count() > 1) c += 5;
        if (e.Ev.Count >= 5) c += 5;
        return Math.Clamp(c, 5, 99);
    }

    static int KindRank(string k) => k switch
    {
        "decoded" => 0, "string" => 1, "bytes" => 2, "blob" => 3, "name" => 4, "import" => 5, _ => 6,
    };

    // Correlation

    static bool MatchMeta(MetaGroup[] groups, Dictionary<string, FlagHit> by, List<FlagHit> used)
    {
        var tmp = new List<FlagHit>();
        foreach (var g in groups)
        {
            var found = g.Ids.Where(by.ContainsKey).Select(i => by[i]).Where(h => h.Severity >= g.MinSev).ToList();
            if (found.Count < g.Min) return false;
            tmp.AddRange(found);
        }
        used.AddRange(tmp);
        return true;
    }

    static List<FlagHit> Correlate(List<FlagHit> hits)
    {
        var by = hits.ToDictionary(h => h.Id);
        var res = new List<FlagHit>();
        foreach (var m in Metas)
        {
            var used = new List<FlagHit>();
            if (!MatchMeta(m.Req, by, used)) continue;
            var sev = m.Sev;
            if (m.UpReq != null && MatchMeta(m.UpReq, by, used)) sev = m.UpSev;
            used = used.Distinct().ToList();

            var ev = used.Select(h => new FlagEvidence
            {
                Kind = "rule",
                Text = $"{h.Label} ({h.Severity})",
                Code = h.Evidence.FirstOrDefault()?.Code,
                Src = h,
            }).ToList();

            int conf = (int)Math.Round(used.Average(h => h.Confidence)) + 10;
            res.Add(new FlagHit
            {
                Id = m.Id, Label = m.Label, Category = "Correlation", Description = m.Desc, Severity = sev,
                TotalEvidence = ev.Count, Evidence = ev, Confidence = Math.Clamp(conf, 40, 95), IsCorrelation = true,
            });
        }
        return res;
    }

    // Public API

    /// <param name="imports">Imports already computed by MainWindow.ComputeImports.</param>
    public static List<FlagHit> Scan(PycFile pyc, List<ImportRec> imports, CancellationToken ct = default)
    {
        var k = new Corpus();
        if (imports != null) foreach (var im in imports) k.AddImport(im);

        var seenStr = new HashSet<string>(StringComparer.Ordinal);
        foreach (var c in pyc.AllCode)
        {
            ct.ThrowIfCancellationRequested();
            k.AddName(c.Name, c);
            foreach (var n in c.Names) k.AddName(n, c);
            foreach (var o in c.Consts) Flatten(o, c, k, 0, seenStr);
        }

        var res = new List<FlagHit>();
        foreach (var r in Rules)
        {
            ct.ThrowIfCancellationRequested();
            var e = Eval(r, k);
            if (e == null) continue;

            var sev = r.Sev;
            if (e.Boosted && r.BoostSev > sev) sev = r.BoostSev;
            if (e.Scattered && sev == Mal) sev = Sus;        // downgrade only, never drop

            var ev = e.Ev.OrderBy(x => KindRank(x.Kind)).ToList();
            res.Add(new FlagHit
            {
                Id = r.Id, Label = r.Label, Category = r.Category, Description = r.Desc, Severity = sev,
                TotalEvidence = ev.Count, Evidence = ev.Take(MaxEvidence).ToList(),
                Confidence = Conf(sev, e, r), Boosted = e.Boosted, Scattered = e.Scattered,
            });
        }

        res.AddRange(Correlate(res));
        res.Sort((a, b) =>
        {
            int c = b.Severity.CompareTo(a.Severity);
            if (c != 0) return c;
            c = b.Confidence.CompareTo(a.Confidence);
            return c != 0 ? c : string.Compare(a.Label, b.Label, StringComparison.OrdinalIgnoreCase);
        });
        return res;
    }

    /// <summary>Overall risk estimate from the hits (weighted by severity and confidence).</summary>
    public static FlagVerdict Assess(List<FlagHit> hits)
    {
        var v = new FlagVerdict();
        if (hits == null || hits.Count == 0)
        {
            v.Level = "No significant indicators";
            v.Summary = "No flags.";
            return v;
        }

        double s = 0, info = 0;
        int mal = 0, sus = 0, inf = 0;
        foreach (var h in hits)
        {
            double w = h.Confidence / 100.0;
            switch (h.Severity)
            {
                case FlagSeverity.Malicious: mal++; s += 30 * w; break;
                case FlagSeverity.Suspicious: sus++; s += 9 * w; break;
                default: inf++; info += 0.7; break;
            }
        }
        s += Math.Min(info, 6);
        v.Score = (int)Math.Min(100, Math.Round(s));

        if (mal >= 2 || v.Score >= 65) v.Level = "Likely malicious";
        else if (mal >= 1 || v.Score >= 25) v.Level = "Suspicious";
        else if (sus >= 1 || v.Score >= 8) v.Level = "Low suspicion";
        else v.Level = "No significant indicators";

        v.Summary = $"{mal} malicious, {sus} suspicious, {inf} informational indicator(s)";
        return v;
    }

    public static string ToText(PycFile pyc, List<FlagHit> hits)
    {
        var sb = new StringBuilder();
        sb.AppendLine($"Opcodex behavior flags - {System.IO.Path.GetFileName(pyc?.Path ?? "")} (Python {pyc?.VersionText})");
        if (hits == null || hits.Count == 0) { sb.AppendLine("No flags."); return sb.ToString(); }

        var v = Assess(hits);
        sb.AppendLine($"Verdict: {v.Level} (score {v.Score}/100) - {v.Summary}");

        foreach (var h in hits)
        {
            sb.AppendLine();
            string tags = (h.Boosted ? " [corroborated]" : "") + (h.Scattered ? " [scattered]" : "") + (h.IsCorrelation ? " [chain]" : "");
            sb.AppendLine($"[{h.Severity}] {h.Label} ({h.Category}) - {h.TotalEvidence} hit(s), confidence {h.Confidence}%{tags}");
            sb.AppendLine($"    {h.Description}");
            foreach (var e in h.Evidence)
            {
                string where = e.Code == null ? "" : "   @ " + (string.IsNullOrEmpty(e.Code.QualName) ? e.Code.Name : e.Code.QualName);
                sb.AppendLine($"    {e.Kind,-8} {e.Text}{where}");
            }
            if (h.TotalEvidence > h.Evidence.Count) sb.AppendLine($"    ... {h.TotalEvidence - h.Evidence.Count} more");
        }
        return sb.ToString();
    }

    // Utilities

    static void Flatten(PyObj o, PyCode c, Corpus k, int depth, HashSet<string> seen)
    {
        if (o == null || depth > 6) return;
        switch (o)
        {
            case PyStr s:
                k.AddString(s.Value, "string", c, seen);
                break;
            case PyBytes b:
                k.AddBytes(b.Data, c, seen);
                break;
            case PyTuple t:
                foreach (var i in t.Items) Flatten(i, c, k, depth + 1, seen);
                break;
            case PyList l:
                foreach (var i in l.Items) Flatten(i, c, k, depth + 1, seen);
                break;
            case PySet st:
                foreach (var i in st.Items) Flatten(i, c, k, depth + 1, seen);
                break;
            case PyDict d:
                foreach (var kv in d.Items) { Flatten(kv.Key, c, k, depth + 1, seen); Flatten(kv.Value, c, k, depth + 1, seen); }
                break;
        }
    }

    static readonly Regex B64Only = new(@"^[A-Za-z0-9+/_\-]{16,}={0,2}$", RegexOptions.Compiled | RegexOptions.CultureInvariant);
    static readonly Regex HexOnly = new(@"^(?:[0-9A-Fa-f]{2}){16,}$", RegexOptions.Compiled | RegexOptions.CultureInvariant);

    static string Reverse(string s)
    {
        var a = s.ToCharArray();
        Array.Reverse(a);
        return new string(a);
    }

    static byte[] DecodeB64Raw(string s)
    {
        if (s == null || s.Length < 16 || s.Length > 200000 || !B64Only.IsMatch(s)) return null;
        try
        {
            string t = s.TrimEnd('=').Replace('-', '+').Replace('_', '/');
            switch (t.Length % 4)
            {
                case 1: return null;
                case 2: t += "=="; break;
                case 3: t += "="; break;
            }
            return Convert.FromBase64String(t);
        }
        catch (FormatException) { return null; }
    }

    static byte[] DecodeHexRaw(string s)
    {
        if (s == null || s.Length < 32 || s.Length > 400000 || (s.Length & 1) != 0 || !HexOnly.IsMatch(s)) return null;
        try { return Convert.FromHexString(s); }
        catch (FormatException) { return null; }
    }

    // Candidate decodings of a string constant: base64, hex, reversed base64 and reversed URLs.
    static IEnumerable<string> Decoders(string text)
    {
        string t = text.Trim();
        string r = Interpret(DecodeB64Raw(t));
        if (r != null) yield return r;
        r = Interpret(DecodeHexRaw(t));
        if (r != null) yield return r;
        if (t.Length >= 16 && t.Length <= 200000)
        {
            if (t.Contains("//:sptth", StringComparison.Ordinal) || t.Contains("//:ptth", StringComparison.Ordinal))
                yield return Reverse(t);
            else
            {
                r = Interpret(DecodeB64Raw(Reverse(t)));
                if (r != null) yield return r;
            }
        }
    }

    static bool HasBinaryMagic(byte[] r) =>
        (r[0] == 'M' && r[1] == 'Z') ||
        (r[0] == 0x7F && r[1] == 'E' && r[2] == 'L' && r[3] == 'F') ||
        (r[0] == 'P' && r[1] == 'K' && r[2] == 3 && r[3] == 4) ||
        (r[0] == 'R' && r[1] == 'a' && r[2] == 'r' && r[3] == '!') ||
        (r[0] == '7' && r[1] == 'z' && r[2] == 0xBC && r[3] == 0xAF);

    static uint U32(byte[] b, int o) => (uint)(b[o] | b[o + 1] << 8 | b[o + 2] << 16 | b[o + 3] << 24);

    // A marshalled code object starts with 0xE3 followed by small ints (argcount/kwonly/nlocals...).
    static bool IsMarshalCode(byte[] r)
    {
        if (r == null || r.Length < 32 || r[0] != 0xE3) return false;
        for (int o = 1; o <= 9; o += 4)
            if (U32(r, o) > 64) return false;
        return true;
    }

    static byte[] TryInflate(byte[] raw)
    {
        if (raw == null || raw.Length < 8) return null;
        try
        {
            var ms = new MemoryStream(raw);
            Stream z;
            if (raw[0] == 0x78 && (raw[1] == 0x01 || raw[1] == 0x5E || raw[1] == 0x9C || raw[1] == 0xDA))
                z = new ZLibStream(ms, CompressionMode.Decompress);
            else if (raw[0] == 0x1F && raw[1] == 0x8B)
                z = new GZipStream(ms, CompressionMode.Decompress);
            else return null;

            using (z)
            {
                var o = new MemoryStream();
                var buf = new byte[16384];
                int n;
                while ((n = z.Read(buf, 0, buf.Length)) > 0)
                {
                    o.Write(buf, 0, n);
                    if (o.Length > MaxInflate) break;        // zip-bomb guard
                }
                return o.Length >= 8 ? o.ToArray() : null;
            }
        }
        catch (InvalidDataException) { return null; }
        catch (IOException) { return null; }
    }

    /// <summary>
    /// Turns decoded bytes into scannable text: executables/archives are kept as Latin-1, compressed data is
    /// inflated, marshalled code is replaced by a marker, and other data must be at least 85% printable.
    /// </summary>
    static string Interpret(byte[] raw, int depth = 0)
    {
        if (raw == null || raw.Length < 8 || depth > 2) return null;
        if (HasBinaryMagic(raw)) return Encoding.Latin1.GetString(raw, 0, Math.Min(raw.Length, MaxStringLen));
        if (IsMarshalCode(raw)) return MarshalMarker;
        var inf = TryInflate(raw);
        if (inf != null) return Interpret(inf, depth + 1);

        int n = Math.Min(raw.Length, 4096), printable = 0;
        for (int i = 0; i < n; i++)
        {
            byte b = raw[i];
            if ((b >= 32 && b < 127) || b == 9 || b == 10 || b == 13) printable++;
        }
        if (printable * 100 < n * 85) return null;
        return Encoding.Latin1.GetString(raw, 0, Math.Min(raw.Length, MaxStringLen));
    }

    static double Entropy(byte[] d, int n)
    {
        var cnt = new int[256];
        for (int i = 0; i < n; i++) cnt[d[i]]++;
        double h = 0;
        for (int i = 0; i < 256; i++)
            if (cnt[i] > 0) { double p = (double)cnt[i] / n; h -= p * Math.Log2(p); }
        return h;
    }

    // Common media/font containers are high-entropy but benign; skip them for the opaque-blob rule.
    static bool LooksLikeMedia(byte[] d)
    {
        if (d.Length < 8) return false;
        if (d[0] == 0x89 && d[1] == 'P' && d[2] == 'N' && d[3] == 'G') return true;                 // PNG
        if (d[0] == 0xFF && d[1] == 0xD8 && d[2] == 0xFF) return true;                              // JPEG
        if (d[0] == 'G' && d[1] == 'I' && d[2] == 'F' && d[3] == '8') return true;                  // GIF
        if (d[0] == 'R' && d[1] == 'I' && d[2] == 'F' && d[3] == 'F') return true;                  // WAV/WebP/AVI
        if (d[0] == 'O' && d[1] == 'g' && d[2] == 'g' && d[3] == 'S') return true;                  // Ogg
        if (d[0] == 'I' && d[1] == 'D' && d[2] == '3') return true;                                 // MP3
        if (d[0] == 'w' && d[1] == 'O' && d[2] == 'F') return true;                                 // WOFF/WOFF2
        if (d[0] == 0 && d[1] == 1 && d[2] == 0 && d[3] == 0) return true;                          // TrueType
        if (d[0] == 'O' && d[1] == 'T' && d[2] == 'T' && d[3] == 'O') return true;                  // OpenType
        if (d[0] == 0 && d[1] == 0 && d[2] == 1 && d[3] == 0) return true;                          // ICO
        return false;
    }

    static string Clean(string s)
    {
        var sb = new StringBuilder(s.Length);
        foreach (char ch in s) sb.Append(ch < 32 || ch == 127 ? ' ' : ch);
        return sb.ToString();
    }

    static string Short(string s, int max)
    {
        s = Clean(s);
        return s.Length <= max ? s : s.Substring(0, max) + "…";
    }

    static string Snip(string text, int idx, int len)
    {
        int from = Math.Max(0, idx - 24);
        int to = Math.Min(text.Length, idx + len + 48);
        string body = Clean(text.Substring(from, to - from));
        return (from > 0 ? "…" : "") + body + (to < text.Length ? "…" : "");
    }
}