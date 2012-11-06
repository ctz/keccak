import glob
import keccak

triggers = ('MD', 'Squeezed')
longinp = 'Text'

def process_kat_short(mkhasher, Len, Msg, MD = None, Squeezed = None):
    Len = int(Len)
    Msg = Msg.decode('hex')
    if MD:
        MD = MD.decode('hex')
    else:
        Squeezed = Squeezed.decode('hex')
    if Len % 8:
        # print 'Length %d is not byte-aligned, skipping test vector' % Len
        return
    
    h = mkhasher()
    h.update(Msg[:Len / 8])
    if MD:
        assert h.digest() == MD
    else:
        assert Squeezed.startswith(h.digest())

def process_kat_long(mkhasher, Text, Repeat, MD = None, Squeezed = None):
    if MD:
        MD = MD.decode('hex')
    else:
        Squeezed = Squeezed.decode('hex')
    Repeat = int(Repeat)
    
    mul = 64
    assert Repeat % mul == 0
    Text *= mul
    
    h = mkhasher()
    for i in range(Repeat / mul):
        h.update(Text)
    if MD:
        assert h.digest() == MD
    else:
        assert Squeezed.startswith(h.digest())

def process_katfile(fn, mkhasher):
    data = {}
    for f in open(fn):
        if len(f.strip()) == 0 or f[0] == '#':
            continue
        lhs, rhs = f.strip().split(' = ', 1)
        data[lhs] = rhs
        
        if lhs in triggers:
            if longinp in data:
                process_kat_long(mkhasher, **data)
            else:
                process_kat_short(mkhasher, **data)
            data = {}

def run_glob(pat, mkhasher):
    for g in glob.glob(pat):
        print 'Processing:', g
        process_katfile(g, mkhasher)

if __name__ == '__main__':
    run_glob('KeccakKAT/*MsgKAT_0.txt', lambda: keccak.KeccakHash(1024, 576, 1024))
    run_glob('KeccakKAT/*MsgKAT_224.txt', lambda: keccak.Keccak224())
    run_glob('KeccakKAT/*MsgKAT_256.txt', lambda: keccak.Keccak256())
    run_glob('KeccakKAT/*MsgKAT_384.txt', lambda: keccak.Keccak384())
    run_glob('KeccakKAT/*MsgKAT_512.txt', lambda: keccak.Keccak512())