import glob
import keccak

triggers = ("MD", "Squeezed", "Output")
longinp = "Text"


def process_kat_short(mkhasher, Len, Msg, MD=None, Squeezed=None):
    Len = int(Len)
    Msg = bytes.fromhex(Msg)
    if MD:
        MD = bytes.fromhex(MD)
    else:
        Squeezed = bytes.fromhex(Squeezed)
    if Len % 8:
        # print('Length %d is not byte-aligned, skipping test vector' % Len)
        return

    h = mkhasher()
    h.update(Msg[: Len // 8])
    if MD:
        assert h.digest() == MD
    else:
        assert Squeezed.startswith(h.digest())


def process_kat_long(mkhasher, Text, Repeat, MD=None, Squeezed=None):
    if MD:
        MD = bytes.fromhex(MD)
    else:
        Squeezed = bytes.fromhex(Squeezed)
    Repeat = int(Repeat)

    mul = 64
    assert Repeat % mul == 0
    Text *= mul

    h = mkhasher()
    for i in range(Repeat // mul):
        h.update(Text)
    if MD:
        assert h.digest() == MD
    else:
        assert Squeezed.startswith(h.digest())


def process_kat_shake(mkhasher, Len, Msg, Output):
    Len = int(Len) // 8
    Msg = bytes.fromhex(Msg)[:Len]
    Output = bytes.fromhex(Output)

    h = mkhasher()
    h.update(Msg)
    got = h.squeeze(len(Output))
    assert got == Output


def process_katfile(fn, mkhasher):
    data = {}
    for f in open(fn):
        if len(f.strip()) == 0 or f[0] in ("#", "["):
            continue
        lhs, rhs = f.strip().split(" = ", 1)
        data[lhs] = rhs

        if lhs in triggers:
            if lhs == "Output":
                process_kat_shake(mkhasher, **data)
            elif longinp in data:
                process_kat_long(mkhasher, **data)
            else:
                process_kat_short(mkhasher, **data)
            data = {}


def run_glob(pat, mkhasher):
    for g in glob.glob(pat):
        print("Processing:", g)
        process_katfile(g, mkhasher)


if __name__ == "__main__":
    run_glob("KeccakKAT/*MsgKAT_0.txt", lambda: keccak.KeccakHash(1024, 576, 1024))
    run_glob("KeccakKAT/*MsgKAT_224.txt", lambda: keccak.Keccak224())
    run_glob("KeccakKAT/*MsgKAT_256.txt", lambda: keccak.Keccak256())
    run_glob("KeccakKAT/*MsgKAT_384.txt", lambda: keccak.Keccak384())
    run_glob("KeccakKAT/*MsgKAT_512.txt", lambda: keccak.Keccak512())
    run_glob("SHA3KAT/SHA3_224*Msg.rsp", lambda: keccak.SHA3_224())
    run_glob("SHA3KAT/SHA3_256*Msg.rsp", lambda: keccak.SHA3_256())
    run_glob("SHA3KAT/SHA3_384*Msg.rsp", lambda: keccak.SHA3_384())
    run_glob("SHA3KAT/SHA3_512*Msg.rsp", lambda: keccak.SHA3_512())
    run_glob("SHA3KAT/SHAKE128*Msg.rsp", lambda: keccak.SHAKE_128())
    run_glob("SHA3KAT/SHAKE256*Msg.rsp", lambda: keccak.SHAKE_256())
