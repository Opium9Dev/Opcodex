"""Vérifie la table de règles de Pyc/Flags.cs sans compiler le C#.

Charge BuildRules() depuis Flags.cs, la traduit en Python (mêmes sémantiques que FlagScanner)
et l'applique à un .pyc :   python tools/verify_flags.py fichier.pyc
Utile pour tester une nouvelle règle rapidement avant de rebuild l'application.
"""
import base64, dis, marshal, re, sys, types
from pathlib import Path

SRC = (Path(__file__).resolve().parent.parent / "Pyc" / "Flags.cs").read_text(encoding="utf-8")


# ---- 1. extraire et traduire la table de règles ------------------------------------------
def verbatim(m):  # @"..."  ->  chaîne Python équivalente
    return '"' + m.group(1).replace("\\", "\\\\").replace('""', '\\"') + '"'

consts = {}
for m in re.finditer(r'const string (\w+) = @"((?:[^"]|"")*)";', SRC):
    consts[m.group(1)] = m.group(2).replace('""', '"')
for m in re.finditer(r'const string (\w+)\s*=\s*"([^"]*)";', SRC):
    consts[m.group(1)] = m.group(2)
for m in re.finditer(r'static readonly string (\w+)\s*=\s*D\("([^"]*)"\);', SRC):
    consts[m.group(1)] = base64.b64decode(m.group(2)).decode("utf-8")
for m in re.finditer(r'static readonly string\[\] (\w+)\s*=\s*\{(.*?)\};', SRC, re.S):
    consts[m.group(1)] = re.findall(r'"([^"]*)"', m.group(2))

body = SRC.split("static List<Rule> BuildRules() => new()")[1].split("\n    };")[0]
body = "\n".join("#" + l.strip()[2:] if l.strip().startswith("//") else l for l in body.splitlines())
body = re.sub(r'@"((?:[^"]|"")*)"', verbatim, body)
body = body.strip().lstrip("{")


class Sig:
    def __init__(s, k, subs=None, rx=None): s.k, s.subs, s.rx = k, subs or [], rx

class Rule(dict):
    def Boost(self, severity, *groups):
        self["boost_sev"] = severity
        self["boost_groups"] = list(groups)
        return self

    def Min(self, count):
        self["min"] = count
        return self

    def Near(self):
        self["near"] = True
        return self

def signals(k, *values, lower=False):
    if len(values) == 1 and isinstance(values[0], list):
        values = values[0]
    return Sig(k, [value.lower() if lower else value for value in values])

env = dict(
    Inf="Info", Sus="Suspicious", Mal="Malicious",
    D=lambda value: base64.b64decode(value).decode("utf-8"),
    M=lambda *a: signals("M", *a, lower=True),
    N=lambda *a: signals("N", *a),
    S=lambda *a: signals("S", *a, lower=True),
    E=lambda: Sig("E"),
    X=lambda rx: Sig("X", rx=re.compile(rx)),
    G=lambda *s: list(s),
    R=lambda i, l, c, sev, d, *g: Rule(id=i, label=l, cat=c, sev=sev, desc=d, groups=list(g)),
    **consts,
)
RULES = eval("[" + body + "]", env)


# ---- 2. corpus ---------------------------------------------------------------------------
def walk(co):
    yield co
    for c in co.co_consts:
        if isinstance(c, types.CodeType):
            yield from walk(c)

B64 = re.compile(r"^[A-Za-z0-9+/_\-]{16,}={0,2}$")
def try_b64(s):
    s = s.strip()
    if len(s) < 16 or not B64.match(s): return None
    t = s.rstrip("=").replace("-", "+").replace("_", "/")
    if len(t) % 4 == 1: return None
    t += "=" * (-len(t) % 4)
    try: raw = base64.b64decode(t)
    except Exception: return None
    if len(raw) < 8: return None
    n = min(len(raw), 4096)
    if sum(1 for b in raw[:n] if 32 <= b < 127 or b in (9, 10, 13)) * 100 < n * 85: return None
    return raw.decode("latin1")

def flatten(o, depth=0):
    if depth > 6: return
    if isinstance(o, str): yield "string", o
    elif isinstance(o, bytes) and len(o) >= 3: yield "bytes", o.decode("latin1")
    elif isinstance(o, (tuple, list, frozenset, set)):
        for i in o: yield from flatten(i, depth + 1)

def build(co_root):
    modules, names, strings, seen = [], {}, [], set()
    for co in walk(co_root):
        ins = list(dis.get_instructions(co))
        for i, x in enumerate(ins):
            if x.opname == "IMPORT_NAME":
                fl = ins[i - 1].argval if i >= 1 and ins[i - 1].opname == "LOAD_CONST" else None
                m = x.argval.lower()
                keys = [m] + ([m + "." + f.lower() for f in fl] if isinstance(fl, tuple) else [])
                modules.append(dict(text=("from %s import %s" % (x.argval, ", ".join(fl)) if isinstance(fl, tuple) else "import " + x.argval), keys=keys, code=co))
        for n in [co.co_name] + list(co.co_names):
            if n and not n.startswith("<"): names.setdefault(n.lower(), []).append(dict(text=n, code=co))
        for c in co.co_consts:
            for kind, s in flatten(c):
                if len(s) < 3 or s in seen: continue
                seen.add(s); strings.append(dict(text=s, low=s.lower(), kind=kind, code=co))
                d = try_b64(s)
                if d and d not in seen:
                    seen.add(d); strings.append(dict(text=d, low=d.lower(), kind="decoded", code=co))
    return modules, names, strings


def collect(sig, corpus):
    modules, names, strings = corpus
    out = []
    if sig.k == "M":
        for m in modules:
            if any(k == a or k.startswith(a + ".") for k in m["keys"] for a in sig.subs):
                out.append(("import", m["text"], m["code"], id(m)))
    elif sig.k == "N":
        for a in sig.subs:
            for it in names.get(a.lower(), []): out.append(("name", it["text"], it["code"], id(it)))
    elif sig.k == "S":
        for it in strings:
            for a in sig.subs:
                i = it["low"].find(a)
                if i >= 0:
                    out.append((it["kind"], it["text"][max(0, i - 24): i + len(a) + 48], it["code"], id(it))); break
    elif sig.k == "X":
        for it in strings:
            m = sig.rx.search(it["text"])
            if m: out.append((it["kind"], m.group(0)[:120], it["code"], id(it)))
    return out

def evaluate(rule, corpus):
    groups, seen = [], set()
    for g in rule["groups"]:
        ev = [e for s in g for e in collect(s, corpus)]
        if not ev: return None
        groups.append(ev)
    if groups and len({e[3] for e in groups[0]}) < rule.get("min", 1): return None
    boosts = rule.get("boost_groups", [])
    if boosts:
        extra = [[e for s in g for e in collect(s, corpus)] for g in boosts]
        if all(extra):
            groups.extend(extra)
    merged = []
    for group in groups:
        for e in group:
            if e[3] not in seen: seen.add(e[3]); merged.append(e)
    return merged


if __name__ == "__main__":
    path = sys.argv[1]
    co = marshal.loads(Path(path).read_bytes()[16:])
    corpus = build(co)
    order = {"Malicious": 0, "Suspicious": 1, "Info": 2}
    hits = [(r, ev) for r in RULES if (ev := evaluate(r, corpus))]
    hits.sort(key=lambda h: (order[h[0]["sev"]], h[0]["label"]))
    print(f"{len(RULES)} rules loaded from Flags.cs, {len(hits)} flag(s) for {Path(path).name}\n")
    for r, ev in hits:
        print(f"[{r['sev']:<10}] {r['label']}  ({r['cat']}, {len(ev)} hit(s))")
        for kind, text, code, _ in ev[:4]:
            print(f"      {kind:<8} {text[:90]!r:<94} @ {code.co_qualname if hasattr(code, 'co_qualname') else code.co_name}")
