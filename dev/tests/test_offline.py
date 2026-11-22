"""Offline checks: CFB round-trip on surveyed blobs, and SRP/framing parity with node-acp."""
import json, os, re, subprocess, sys
sys.path.insert(0, os.path.join(os.path.dirname(os.path.abspath(__file__)), "..", "..", "AirPort.indigoPlugin", "Contents", "Server Plugin"))
from airport_acp import cflbinary, message, values
from airport_acp.srp import SRPClient

SURVEY = os.path.expanduser("~/acp-test/survey/all.txt")
NODE_DIR = os.path.expanduser("~/acp-test")

def survey_values():
    out = {}
    for line in open(SURVEY):
        m = re.match(r"^Prop (.{4}) value: (\{.*\})\s*$", line)
        if m:
            out[m.group(1)] = bytes(json.loads(m.group(2))["data"])
    return out

def node(js):
    env = dict(os.environ)
    return subprocess.run(["node", "-e", js], cwd=NODE_DIR, capture_output=True, text=True, env=env, check=True).stdout

def test_cfb_roundtrip():
    vals = survey_values()
    ok = bad = 0
    for name, raw in vals.items():
        if values.type_of(name) != "cfb":
            continue
        obj = cflbinary.parse(raw)
        if cflbinary.compose(obj) == raw:
            ok += 1
        else:
            bad += 1
            print("  ROUND-TRIP MISMATCH:", name)
    print("CFB round-trip: %d byte-identical, %d mismatched" % (ok, bad))
    return bad == 0

def test_decode_all():
    vals = survey_values()
    failed = [n for n, raw in vals.items() if values.type_of(n) != "bin" and isinstance(values.decode(n, raw), bytes)]
    print("Typed decode: %d properties, %d fell back to raw bytes %s" % (len(vals), len(failed), failed))
    return not failed

def test_srp_matches_fast_srp():
    secret = os.urandom(32); salt = os.urandom(16); pw = "correct horse"
    # Use the real ACP 1536-bit group via fast-srp-hap's params, and a server B from its Server.
    js = r"""
const srp=require('fast-srp-hap'); const p=srp.params[1536];
const salt=Buffer.from('%s','hex'), secret=Buffer.from('%s','hex');
const b=require('crypto').randomBytes(32);
const s=new srp.Server(p,salt,Buffer.from('admin'),Buffer.from('%s'),b); const B=s.computeB();
c_check=s;
const params={N_length_bits:1536,N:p.N,g:p.g,hash:'sha1'};
const c=new srp.Client(params,salt,Buffer.from('admin'),Buffer.from('%s'),secret);
c.setB(B); s.setA(c.computeA()); s.checkM1(c.computeM1());
console.log(JSON.stringify({N:p.N.toBuffer(true).toString('hex'),g:p.g.toBuffer(true).toString('hex'),
 B:B.toString('hex'),A:c.computeA().toString('hex'),M1:c.computeM1().toString('hex'),K:c.computeK().toString('hex')}));
""" % (salt.hex(), secret.hex(), pw, pw)
    ref = json.loads(node(js))
    c = SRPClient(pw, salt, bytes.fromhex(ref["g"]), bytes.fromhex(ref["N"]), bytes.fromhex(ref["B"]), _secret=secret)
    same = (c.public.hex() == ref["A"], c.proof.hex() == ref["M1"], c.session_key.hex() == ref["K"])
    print("SRP vs fast-srp-hap: A %s, M1 %s, K %s" % tuple("match" if s else "DIFFER" for s in same))
    return all(same)

def test_framing_matches_node():
    body = b"".join(message.pack_element(n) for n in ["syNm", "WiFi", "syUT"])
    py = message.compose(message.CMD_GET_PROPERTY, 4, message.ZERO_KEY, body)
    js = r"""
const M=require('node-acp/dist/lib/message').default; const P=require('node-acp/dist/lib/property').default;
const body=Buffer.concat(['syNm','WiFi','syUT'].map(n=>P.composeRawElement(0,new P(n))));
const a=M.composeGetPropCommand(4,null,body).composeRawPacket();
const auth=M.composeAuthCommand(4,Buffer.from('test')).composeRawPacket();
console.log(a.toString('hex')+' '+auth.toString('hex'));
"""
    ref_get, ref_auth = node(js).split()
    py_auth = message.compose(message.CMD_AUTHENTICATE, 4, message.header_key(""), b"test")
    same = (py.hex() == ref_get, py_auth.hex() == ref_auth)
    print("Framing vs node-acp: get-prop %s, auth %s" % tuple("match" if s else "DIFFER" for s in same))
    return all(same)

if __name__ == "__main__":
    results = [t() for t in (test_cfb_roundtrip, test_decode_all, test_srp_matches_fast_srp, test_framing_matches_node)]
    print("ALL PASSED" if all(results) else "FAILURES ABOVE")

def test_session_cipher_matches_node():
    from airport_acp.client import _StreamCipher
    key, civ, siv = os.urandom(40), os.urandom(16), os.urandom(16)
    data = os.urandom(300)
    c = _StreamCipher(key, civ, siv)
    py = c.encrypt(data[:100]) + c.encrypt(data[100:])
    js = r"""
const {Encryption}=require('node-acp/dist/lib/session');
const e=new Encryption(Buffer.from('%s','hex'),Buffer.from('%s','hex'),Buffer.from('%s','hex'));
console.log(e.clientEncrypt(Buffer.from('%s','hex')).toString('hex'));
""" % (key.hex(), civ.hex(), siv.hex(), data.hex())
    same = node(js).strip() == py.hex()
    print("Session cipher vs node-acp:", "match" if same else "DIFFER")
    return same

if __name__ == "__main__":
    print("ALL PASSED" if test_session_cipher_matches_node() else "CIPHER FAILURE")
