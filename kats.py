import glob, fnmatch, re
from binascii import hexlify, unhexlify
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


def process_kat_shake(mkhasher, Len, Msg, Output, Outputlen=None, COUNT=None):
    if not Len:
        Len=len(bytes.fromhex(Msg)) * 8

    Len = int(Len) // 8
    Msg = bytes.fromhex(Msg)[:Len]
    Output = bytes.fromhex(Output)

    if Outputlen:
        assert (int(Outputlen) // 8) == len(Output)

    h = mkhasher()
    h.update(Msg)
    got = h.squeeze(len(Output))
    assert got == Output


def process_katfile_turboshake(fn):
    # The test pattern specified in RFC9861
    def ptn(n):
        return bytes([(j % 251) for j in range(n)])

    def parse_input(m_str):
        if m_str == "`00`^0":
            return b""
        elif (m := re.match("ptn\\(17\\*\\*([0-9]+) bytes\\)", m_str)) is not None:
            return ptn(17**int(m.group(1)))
        elif (m := re.match("`(.*)`", m_str)) is not None:
            return unhexlify(m.group(1).replace(" ", ""))
        else:
            return None

    def process_kat_turboshake(mkhasher, Len, Msg, Output):
        Msg = bytes.fromhex(Msg)
        Output = bytes.fromhex(Output)

        h = mkhasher()
        h.update(Msg)
        got = h.squeeze(Len)
        got = got[-len(Output):] # some tests only give the last n bytes
        assert got == Output

    print("Processing:", fn)
    Output = ""
    file = open(fn)
    for f in file.read().split("\n\n"):
        g = f.strip()
        if len(g) == 0 or g[0] in ("#", "["):
            continue

        m = re.match("TurboSHAKE(128|256)\\(M=([^,]*), D=`([^`]*)`, ([0-9]+)\\)(, last [0-9]+ bytes)?:[\n ]*`([^`]*)`", g)
        if m:
            h = m.groups()
            Msg = hexlify(parse_input(h[1]))
            ds = int(unhexlify(h[2])[0])
            Len = int(h[3])
            Output = h[5].replace("\n", "").replace(" ", "")

            # skip long messages to keep test time down
            if len(Msg) > 2000000:
                #print("Skipping vector (long message):", g.split(":")[0])
                continue

            if int(h[0]) == 128:
                mkhasher = keccak.TurboSHAKE.preset(1344, 256, domain_sep=ds)
            elif int(h[0]) == 256:
                mkhasher = keccak.TurboSHAKE.preset(1088, 512, domain_sep=ds)
            else:
                continue
            process_kat_turboshake(mkhasher, Len, Msg, Output)
        #else:
        #    print("Ignoring vector:", g.split(":")[0])


def process_katfile(fn, mkhasher):
    data = {}
    for f in open(fn):
        if len(f.strip()) == 0 or f[0] in ("#", "["):
            continue
        lhs, rhs = f.strip().split(" = ", 1)
        data[lhs] = rhs

        if lhs in triggers:
            if lhs == "Output":
                if "Len" not in data: data["Len"] = 0
                process_kat_shake(mkhasher, **data)
            elif longinp in data:
                process_kat_long(mkhasher, **data)
            else:
                process_kat_short(mkhasher, **data)
            data = {}


def run_glob(pat, mkhasher):
    for g in glob.glob(pat):
        if fnmatch.fnmatch(g, "*ExtremelyLong*") or fnmatch.fnmatch(g, "*Monte*"):
            print("Ignoring:", g)
        else:
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
    run_glob("SHA3KAT/SHAKE128*.rsp", lambda: keccak.SHAKE_128())
    run_glob("SHA3KAT/SHAKE256*.rsp", lambda: keccak.SHAKE_256())
    process_katfile_turboshake("TurboSHAKE_KATS.txt")
