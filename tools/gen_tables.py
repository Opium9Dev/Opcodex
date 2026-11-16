#!/usr/bin/env python3
"""Generates Opcodex/Pyc/OpcodeTables.g.cs from the real CPython sources
(Lib/opcode.py, Lib/_opcode_metadata.py, Include/internal/pycore_opcode_metadata.h).

Run with a 3.13 interpreter (needs the 3.13 `_opcode` module for nb_ops / intrinsics names).
"""
import importlib.util, os, re, sys, types, json

ROOT = os.path.dirname(os.path.abspath(__file__))
VERSIONS = [(3, 8, "c38"), (3, 9, "c39"), (3, 10, "c310"), (3, 11, "c311"), (3, 12, "c312"),
            (3, 13, "c313"), (3, 14, "c314"), (3, 15, "cmain")]

F_ARG, F_CONST, F_NAME, F_JREL, F_JABS, F_LOCAL, F_FREE, F_COMPARE, F_EXC = 1, 2, 4, 8, 16, 32, 64, 128, 256


import builtins
if not hasattr(builtins, "frozendict"):  # 3.15 builtin, emulate for exec'ing metadata under 3.13
    builtins.frozendict = lambda *a, **k: dict(*a, **k)


def load_module(path, name):
    spec = importlib.util.spec_from_file_location(name, path)
    m = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(m)
    return m


def gen_old(major, minor, d):
    """3.8 .. 3.12 : pure-python opcode.py"""
    m = load_module(f"{ROOT}/{d}/Lib/opcode.py", f"opc_{minor}")
    names, flags, caches = {}, {}, {}
    have_arg = m.HAVE_ARGUMENT
    for name, op in m.opmap.items():
        if op >= 256:  # pseudo-instructions are never in a .pyc
            continue
        names[op] = name
        f = 0
        if op >= have_arg: f |= F_ARG
        if op in m.hasconst: f |= F_CONST
        if op in m.hasname: f |= F_NAME
        if op in m.hasjrel: f |= F_JREL
        if op in m.hasjabs: f |= F_JABS
        if op in m.haslocal: f |= F_LOCAL
        if op in m.hasfree: f |= F_FREE
        if op in m.hascompare: f |= F_COMPARE
        if op in getattr(m, "hasexc", []): f |= F_EXC
        flags[op] = f
    ice = getattr(m, "_inline_cache_entries", None)
    if ice is not None:
        for op, name in names.items():
            c = ice[op] if isinstance(ice, (list, tuple)) else ice.get(name, 0)
            if c: caches[op] = c
    nb = [x[1] if isinstance(x, tuple) else x for x in getattr(m, "_nb_ops", [])]
    return dict(names=names, flags=flags, caches=caches, have_arg=have_arg,
                cmp=list(m.cmp_op), nb=nb, extended_arg=m.EXTENDED_ARG)


FLAG_BITS = {"HAS_ARG_FLAG": F_ARG, "HAS_CONST_FLAG": F_CONST, "HAS_NAME_FLAG": F_NAME,
             "HAS_JUMP_FLAG": F_JREL, "HAS_FREE_FLAG": F_FREE, "HAS_LOCAL_FLAG": F_LOCAL}


def gen_new(major, minor, d):
    """3.13+ : _opcode_metadata.py + pycore_opcode_metadata.h"""
    meta = load_module(f"{ROOT}/{d}/Lib/_opcode_metadata.py", f"opm_{minor}")
    hdr = open(f"{ROOT}/{d}/Include/internal/pycore_opcode_metadata.h", encoding="utf-8").read()
    # [NAME] = { true, INSTR_FMT_x, FLAGS },
    fl = {}
    for m in re.finditer(r"\[(\w+)\]\s*=\s*\{\s*(?:true|false)\s*,\s*\w+\s*,\s*([^}]*)\}", hdr):
        bits = 0
        for tok in re.findall(r"HAS_\w+_FLAG", m.group(2)):
            bits |= FLAG_BITS.get(tok, 0)
        fl[m.group(1)] = bits
    # caches
    mc = re.search(r"_PyOpcode_Caches\[256\]\s*=\s*\{(.*?)\};", hdr, re.S)
    cache_by_name = {n: int(v) for n, v in re.findall(r"\[(\w+)\]\s*=\s*(\d+)", mc.group(1))}
    names, flags, caches = {}, {}, {}
    for name, op in meta.opmap.items():
        if op >= 256: continue
        names[op] = name
        f = fl.get(name, 0)
        if name == "COMPARE_OP": f |= F_COMPARE
        if name in ("SETUP_FINALLY", "SETUP_CLEANUP", "SETUP_WITH"): f |= F_EXC
        flags[op] = f
        if cache_by_name.get(name): caches[op] = cache_by_name[name]
    import _opcode
    nb = [x[1] for x in _opcode.get_nb_ops()]
    if minor >= 14 and len(nb) == 26:
        nb.append("[]")  # NB_SUBSCR (3.14+), verified in Include/opcode.h of main
    return dict(names=names, flags=flags, caches=caches, have_arg=meta.HAVE_ARGUMENT,
                cmp=["<", "<=", "==", "!=", ">", ">="], nb=nb, extended_arg=meta.opmap["EXTENDED_ARG"])


def cs_str(s):
    return '"' + s.replace("\\", "\\\\").replace('"', '\\"') + '"'


def gen_runtime(major, minor):
    """Read opcode metadata from the matching installed CPython interpreter."""
    import dis, opcode, _opcode
    if sys.version_info[:2] != (major, minor):
        sys.exit(f"Run this mode with Python {major}.{minor}.")
    flags = {}
    for members, bit in (
        (opcode.hasconst, F_CONST),
        (opcode.hasname, F_NAME),
        (opcode.hasjrel, F_JREL),
        (opcode.hasjabs, F_JABS),
        (opcode.haslocal, F_LOCAL),
        (opcode.hasfree, F_FREE),
        (opcode.hascompare, F_COMPARE),
        (opcode.hasexc, F_EXC),
    ):
        for member in members:
            if member < 256:
                flags[member] = flags.get(member, 0) | bit
    names = {op: name for name, op in opcode.opmap.items() if op < 256}
    for op in opcode.hasarg:
        if op < 256:
            flags[op] = flags.get(op, 0) | F_ARG
    caches = {
        names[op]: dis._inline_cache_entries.get(names[op], 0)
        for op in names
        if dis._inline_cache_entries.get(names[op], 0)
    }
    return dict(
        names=names,
        flags=flags,
        caches=caches,
        have_arg=opcode.HAVE_ARGUMENT,
        cmp=["<", "<=", "==", "!=", ">", ">="],
        nb=[item[1] for item in _opcode.get_nb_ops()],
        extended_arg=opcode.EXTENDED_ARG,
    )


def refresh_runtime_table(minor):
    major = 3
    data = gen_runtime(major, minor)
    lines = [
        f"            case {minor}:",
        f"                t.HaveArgument = {data['have_arg']}; t.ExtendedArg = {data['extended_arg']};",
        "                t.Cmp = new string[] { " + ", ".join(cs_str(s) for s in data["cmp"]) + " };",
        "                t.NbOps = new string[] { " + ", ".join(cs_str(s) for s in data["nb"]) + " };",
    ]
    for op in sorted(data["names"]):
        name = data["names"][op]
        lines.append(
            f"                t.Add({op}, {cs_str(name)}, {data['flags'].get(op, 0)}, {data['caches'].get(name, 0)});"
        )
    lines.extend(["                break;", ""])

    path = os.path.join(ROOT, "..", "Pyc", "OpcodeTables.Generated.cs")
    source = open(path, encoding="utf-8").read()
    start = source.index(f"            case {minor}:")
    end = source.index("                break;", start) + len("                break;")
    source = source[:start] + "\n".join(lines).rstrip() + source[end:]
    open(path, "w", encoding="utf-8", newline="\n").write(source)
    print("refreshed Python", f"{major}.{minor}", "opcode table in", path)


def main():
    if len(sys.argv) == 3 and sys.argv[1] == "--refresh-runtime":
        refresh_runtime_table(int(sys.argv[2]))
        return
    import _opcode
    intr1 = list(_opcode.get_intrinsic1_descs())
    intr2 = list(_opcode.get_intrinsic2_descs())
    out = []
    w = out.append
    w("// <auto-generated> by gen_tables.py from CPython sources (opcode.py / _opcode_metadata.py / pycore_opcode_metadata.h).")
    w("// Do not edit by hand: re-run the generator. </auto-generated>")
    w("using System.Collections.Generic;")
    w("")
    w("namespace Opcodex.Pyc;")
    w("")
    w("public sealed partial class OpcodeTable")
    w("{")
    w("    public const int FArg = 1, FConst = 2, FName = 4, FJRel = 8, FJAbs = 16, FLocal = 32, FFree = 64, FCompare = 128, FExc = 256;")
    w("")
    w("    static readonly string[] Intrinsic1 = { " + ", ".join(cs_str(s) for s in intr1) + " };")
    w("    static readonly string[] Intrinsic2 = { " + ", ".join(cs_str(s) for s in intr2) + " };")
    w("")
    w("    static OpcodeTable Build(int major, int minor)")
    w("    {")
    w("        var t = new OpcodeTable { Major = major, Minor = minor };")
    w("        switch (minor)")
    w("        {")
    for major, minor, d in VERSIONS:
        data = gen_old(major, minor, d) if minor <= 12 else gen_new(major, minor, d)
        w(f"            case {minor}:")
        w(f"                t.HaveArgument = {data['have_arg']}; t.ExtendedArg = {data['extended_arg']};")
        w("                t.Cmp = new string[] { " + ", ".join(cs_str(s) for s in data["cmp"]) + " };")
        w("                t.NbOps = new string[] { " + ", ".join(cs_str(s) for s in data["nb"]) + " };")
        for op in sorted(data["names"]):
            c = data["caches"].get(op, 0)
            w(f"                t.Add({op}, {cs_str(data['names'][op])}, {data['flags'][op]}, {c});")
        w("                break;")
    w("        }")
    w("        return t;")
    w("    }")
    w("}")
    path = os.path.join(ROOT, "..", "Pyc", "OpcodeTables.Generated.cs")
    open(path, "w", encoding="utf-8", newline="\n").write("\n".join(out) + "\n")
    print("wrote", path)


if __name__ == "__main__":
    main()
