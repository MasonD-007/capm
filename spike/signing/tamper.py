import json, sys, base64, copy
src, outdir, kind = sys.argv[1], sys.argv[2], sys.argv[3]


def flip(s):
    raw = bytearray(base64.b64decode(s))
    raw[len(raw) // 2] ^= 1
    return base64.b64encode(bytes(raw)).decode()


b = json.load(open(src))
vm = b['verificationMaterial']
variants = {}

v = copy.deepcopy(b)
if 'messageSignature' in v:
    v['messageSignature']['signature'] = flip(v['messageSignature']['signature'])
else:
    v['dsseEnvelope']['signatures'][0]['sig'] = flip(v['dsseEnvelope']['signatures'][0]['sig'])
variants['tamper-signature'] = v

v = copy.deepcopy(b)
c = v['verificationMaterial'].get('certificate')
if c:
    c['rawBytes'] = flip(c['rawBytes'])
else:
    ch = v['verificationMaterial']['x509CertificateChain']['certificates'][0]
    ch['rawBytes'] = flip(ch['rawBytes'])
variants['tamper-certificate'] = v

v = copy.deepcopy(b)
e = v['verificationMaterial']['tlogEntries'][0]
if 'inclusionProof' in e:
    e['inclusionProof']['hashes'][0] = flip(e['inclusionProof']['hashes'][0])
    variants['tamper-inclusion-proof'] = v

v = copy.deepcopy(b)
v['verificationMaterial']['tlogEntries'][0]['inclusionPromise']['signedEntryTimestamp'] = flip(
    v['verificationMaterial']['tlogEntries'][0]['inclusionPromise']['signedEntryTimestamp'])
variants['tamper-set'] = v

v = copy.deepcopy(b)
v['verificationMaterial']['tlogEntries'] = []
variants['strip-tlog'] = v

for name, vv in variants.items():
    json.dump(vv, open('%s/%s-%s.json' % (outdir, kind, name), 'w'))
    print(name)
