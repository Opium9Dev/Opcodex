import sys, dis, types, importlib, opcode, marshal
assert sys.version_info[:2]==(3,12)

# ---------------- location table (3.11+) ----------------
def rd_varint_le(d,p):
    b=d[p]; p+=1; v=b&63; sh=0
    while b&64:
        b=d[p]; p+=1; sh+=6; v|=(b&63)<<sh
    return v,p
def rd_svarint(d,p):
    v,p=rd_varint_le(d,p); return (-(v>>1) if v&1 else v>>1),p
def decode_loc(tab, first):
    out=[]; line=first; p=0
    while p<len(tab):
        b=tab[p]; p+=1
        code=(b>>3)&15; n=(b&7)+1
        if code==15: loc=(-1,-1,-1,-1)
        elif code==14:
            dl,p=rd_svarint(tab,p); line+=dl
            el,p=rd_varint_le(tab,p); c,p=rd_varint_le(tab,p); ec,p=rd_varint_le(tab,p)
            loc=(line,line+el,c-1,ec-1)
        elif code==13:
            dl,p=rd_svarint(tab,p); line+=dl; loc=(line,line,-1,-1)
        elif code>=10:
            line+=code-10; c=tab[p]; ec=tab[p+1]; p+=2; loc=(line,line,c,ec)
        else:
            s=tab[p]; p+=1; c=(code<<3)|(s>>4); loc=(line,line,c,c+(s&15))
        out += [loc]*n
    return out
def wr_varint_le(v):
    r=bytearray()
    while v>=64: r.append(64|(v&63)); v>>=6
    r.append(v); return r
def wr_svarint(v): return wr_varint_le(((-v)<<1)|1 if v<0 else v<<1)
def encode_loc(locs, first):
    out=bytearray(); prev=first; i=0
    while i<len(locs):
        j=i
        while j<len(locs) and locs[j]==locs[i] and j-i<8: j+=1
        n=j-i; l,el,c,ec=locs[i]; hdr=lambda code: 0x80|(code<<3)|(n-1)
        if l==-1: out.append(hdr(15))
        elif c==-1:
            out.append(hdr(13)); out+=wr_svarint(l-prev); prev=l
        elif el==l and l==prev and c<80 and 0<=ec-c<=15:
            out.append(hdr(c>>3)); out.append(((c&7)<<4)|(ec-c))
        elif el==l and 0<=l-prev<=2 and c<256 and ec<256 and c>=0 and ec>=0:
            out.append(hdr(10+l-prev)); out.append(c); out.append(ec); prev=l
        else:
            out.append(hdr(14)); out+=wr_svarint(l-prev); out+=wr_varint_le(el-l); out+=wr_varint_le(c+1); out+=wr_varint_le(ec+1); prev=l
        i=j
    return bytes(out)

# ---------------- exception table (big-endian varints) ----------------
def rd_varint_be(d,p):
    b=d[p]; p+=1; v=b&63
    while b&64:
        v<<=6; b=d[p]; p+=1; v|=b&63
    return v,p
def decode_exc(tab):
    p=0; res=[]
    while p<len(tab):
        s,p=rd_varint_be(tab,p); l,p=rd_varint_be(tab,p); t,p=rd_varint_be(tab,p); dl,p=rd_varint_be(tab,p)
        res.append((s,s+l,t,dl>>1,dl&1))
    return res
def wr_varint_be(v, first):
    groups=[]
    while True:
        groups.append(v&63); v>>=6
        if not v: break
    groups.reverse(); out=bytearray()
    for i,g in enumerate(groups):
        b=g|(64 if i<len(groups)-1 else 0)
        if i==0 and first: b|=0x80
        out.append(b)
    return out
def encode_exc(entries):
    out=bytearray()
    for s,e,t,d,l in entries:
        out+=wr_varint_be(s,True); out+=wr_varint_be(e-s,False); out+=wr_varint_be(t,False); out+=wr_varint_be((d<<1)|l,False)
    return bytes(out)

def walk(co):
    yield co
    for c in co.co_consts:
        if isinstance(c,types.CodeType): yield from walk(c)

mods=['json.decoder','argparse','typing','asyncio.base_events','dataclasses','inspect','re._parser','decimal','_pydecimal','email._header_value_parser','ast','tarfile']
n=0; bad=0
for m in mods:
    try: mod=importlib.import_module(m)
    except Exception as e: print('skip',m,e); continue
    src=open(mod.__file__,encoding='utf-8').read()
    top=compile(src,mod.__file__,'exec')
    for co in walk(top):
        n+=1
        locs=decode_loc(co.co_linetable, co.co_firstlineno)
        ref=list(co.co_positions())
        assert len(locs)==len(co.co_code)//2
        got=[(a if a is not None else -1, b if b is not None else -1, c if c is not None else -1, d if d is not None else -1) for a,b,c,d in ref]
        # compare decode against CPython (none-lines are (None...) -> -1)
        # when line None, cols None too
        if got!=locs:
            # code 13 'no columns' gives (l,l,None,None)
            bad+=1; print('decode mismatch',co.co_name);
            for i,(x,y) in enumerate(zip(got,locs)):
                if x!=y: print(i,x,y); break
            continue
        new=encode_loc(locs, co.co_firstlineno)
        co2=co.replace(co_linetable=new)
        if list(co2.co_positions())!=ref: bad+=1; print('encode mismatch',co.co_name)
        ex=decode_exc(co.co_exceptiontable)
        if encode_exc(ex)!=co.co_exceptiontable: bad+=1; print('exc mismatch',co.co_name)
print('code objects',n,'bad',bad)
