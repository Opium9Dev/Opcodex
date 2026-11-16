import sys, dis, types, opcode
from proto import *   # reuse codecs (also runs its test loop; fine)
OP=opcode.opmap; NAME={v:k for k,v in OP.items()}
EXT=OP['EXTENDED_ARG']; HAVE=opcode.HAVE_ARGUMENT
CACHES=opcode._inline_cache_entries
minor=12
class E:
    def __init__(s,op,arg,caches,cachedata=None):
        s.op=op;s.arg=arg;s.caches=caches;s.cache=cachedata or bytes(2*caches)
        s.old_start=-1; s.old_main=-1; s.target=None; s.map_start=-1; s.loc_src=None; s.ext=0
def is_jump(op): return op in opcode.hasjrel or op in opcode.hasjabs
def backward(op): return 'BACKWARD' in NAME[op]
def decode(code):
    ins=[]; i=0; ext=0; start=-1
    while i<len(code):
        op=code[i]; raw=code[i+1]
        if start<0: start=i
        has=op>=HAVE
        arg=(raw|ext) if has else -1
        if op==EXT: ext=arg<<8; i+=2; continue
        ext=0
        c=CACHES[op] if op<len(CACHES) else 0
        e=E(op,arg,c,bytes(code[i+2:i+2+2*c])); e.old_start=start; e.old_main=i; e.old_ext=(i-start)//2
        ins.append(e); i+=2+2*c; start=-1
    byst={e.old_start:e for e in ins}
    for e in ins:
        if is_jump(e.op):
            if e.op in opcode.hasjabs: t=e.arg*2
            else:
                t=e.old_main+2+(-e.arg if backward(e.op) else e.arg)*2+2*e.caches
            e.target=byst[t]
    return ins
def ext_needed(a): return 0 if a<256 else 1 if a<65536 else 2 if a<1<<24 else 3
def encode(ins):
    for e in ins: e.ext=ext_needed(e.arg) if not is_jump(e.op) else ext_needed(e.arg)
    for _ in range(50):
        pos=0
        for e in ins:
            e.start=pos; e.main=pos+2*e.ext; pos+=2*(e.ext+1+e.caches)
        total=pos; ch=False
        for e in ins:
            if is_jump(e.op):
                tgt=e.target.start
                if e.op in opcode.hasjabs: a=tgt//2
                else:
                    base=e.main+2+2*e.caches
                    d=(base-tgt) if backward(e.op) else (tgt-base)
                    assert d>=0, 'bad direction'
                    a=d//2
                e.arg=a
                if ext_needed(a)>e.ext: e.ext=ext_needed(a); ch=True
        if not ch: break
    out=bytearray()
    for e in ins:
        for k in range(e.ext,0,-1): out+=bytes([EXT,(e.arg>>(8*k))&255])
        out+=bytes([e.op,(e.arg&255) if e.op>=HAVE else 0]); out+=e.cache
    return bytes(out), total
def rebuild(co, ins):
    # per-unit old locs
    oldloc=decode_loc(co.co_linetable, co.co_firstlineno)
    code,total=encode(ins)
    # loc
    nl=[]
    for e in ins:
        src=e.loc_src or e
        m=src.old_main//2
        for _ in range(e.ext+1): nl.append(oldloc[m])
        for k in range(e.caches):
            nl.append(oldloc[m+1+k] if src is e else oldloc[m])
    # group map
    gm={}; pending=-1
    for e in ins:
        if e.map_start<0 and e.old_start<0:
            if pending<0: pending=e.start
        else:
            key=e.old_start if e.old_start>=0 else e.map_start
            if key not in gm: gm[key]=pending if pending>=0 else e.start
            pending=-1
    oldlen=len(co.co_code); gm[oldlen]=pending if pending>=0 else total
    ex=[]
    for s,e,t,d,l in decode_exc(co.co_exceptiontable):
        def mp(u):
            o=u*2
            while o not in gm: o+=2
            return gm[o]//2
        ex.append((mp(s),mp(e),mp(t),d,l))
    return co.replace(co_code=code, co_linetable=encode_loc(nl, co.co_firstlineno), co_exceptiontable=encode_exc(ex), co_stacksize=co.co_stacksize+4)

# 1. identity round trip on lots of code
n=bad=0
for m in mods:
    try: mod=importlib.import_module(m)
    except Exception: continue
    top=compile(open(mod.__file__,encoding='utf-8').read(),mod.__file__,'exec')
    for co in walk(top):
        n+=1
        ins=decode(co.co_code)
        c2=rebuild(co,ins)
        if c2.co_code!=co.co_code or c2.co_exceptiontable!=co.co_exceptiontable or list(c2.co_positions())!=list(co.co_positions()):
            bad+=1
            if bad<5: print('identity mismatch',co.co_name, c2.co_code==co.co_code, c2.co_exceptiontable==co.co_exceptiontable)
print('identity: code objects',n,'bad',bad)

# 2. insert NOPs (forces jump arg growth + EXTENDED_ARG) and execute
src='''
def f(n):
    t=0
    for i in range(n):
        try:
            if i%3==0: raise ValueError(i)
            t+=i
        except ValueError as e:
            t-=1
        finally:
            t+=100
        while t>1000: t-=7
    return t, [x*2 for x in range(3)], (lambda a: a+1)(4)
'''
ns={}; exec(src,ns); f=ns['f']; ref=f(30)
def patch(co, every, count):
    ins=decode(co.co_code)
    out=[]
    for k,e in enumerate(ins):
        if k%every==0 and e.op not in (OP['RESUME'],):
            for _ in range(count):
                nop=E(OP['NOP'],0,0); nop.loc_src=e; out.append(nop)
        out.append(e)
    c=rebuild(co,out)
    new=[]
    for cst in c.co_consts:
        new.append(patch(cst,every,count) if isinstance(cst,types.CodeType) else cst)
    return c.replace(co_consts=tuple(new))
for every,count in [(1,1),(3,2),(2,200),(1,300)]:
    f2=types.FunctionType(patch(f.__code__,every,count), ns)
    r=f2(30)
    assert r==ref,(every,count,r,ref)
    print('exec ok every',every,'count',count,'code size',len(f2.__code__.co_code),'maxext',max(e.ext for e in decode(f2.__code__.co_code)))
