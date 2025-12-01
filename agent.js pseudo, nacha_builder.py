#!/usr/bin/env python3
import json, hashlib, sys
from pathlib import Path

def canonical_json(obj):
    # deterministic JSON: sorted keys, no spaces
    return json.dumps(obj, separators=(',', ':'), sort_keys=True, ensure_ascii=False)

def sha256_hex(s: bytes) -> str:
    return hashlib.sha256(s).hexdigest()

def merkle_root_from_hex_hashes(hex_hashes):
    if not hex_hashes:
        return None, []
    layers = [hex_hashes[:]]
    nodes = hex_hashes[:]
    while len(nodes) > 1:
        nxt = []
        for i in range(0, len(nodes), 2):
            left = nodes[i]
            right = nodes[i+1] if i+1 < len(nodes) else nodes[i]
            combined = bytes.fromhex(left) + bytes.fromhex(right)
            nxt.append(sha256_hex(combined))
        layers.append(nxt)
        nodes = nxt
    return nodes[0], layers

def main(file_path):
    p = Path(file_path)
    if not p.exists():
        print("file not found:", file_path); return 2
    obj = json.loads(p.read_text(encoding='utf-8'))
    # payload hash
    payload_canon = canonical_json(obj).encode('utf-8')
    payload_hash = sha256_hex(payload_canon)

    # leaf hashes: one per top-level field; include the key to avoid collisions
    leaf_hashes = []
    leaves = []
    for key in sorted(obj.keys()):
        canon = canonical_json({key: obj[key]}).encode('utf-8')
        h = sha256_hex(canon)
        leaf_hashes.append(h)
        leaves.append({"field": key, "canonical": canon.decode('utf-8'), "hash": h})

    root, layers = merkle_root_from_hex_hashes(leaf_hashes)

    out = {
        "payload_hash": payload_hash,
        "merkle_root": root,
        "leaf_count": len(leaf_hashes),
        "leaves": leaves,
        "layers_count": len(layers),
        "layers": layers
    }
    out_path = p.parent / (p.stem + "_attestation.json")
    out_path.write_text(json.dumps(out, indent=2), encoding='utf-8')
    print("Wrote attestation:", out_path)
    print("payload_hash:", payload_hash)
    print("merkle_root:", root)

if __name__ == "__main__":
    if len(sys.argv) < 2:
        print("Usage: compute_attestation.py attested_ach_cleaned.json")
        sys.exit(1)
    sys.exit(main(sys.argv[1]))

// node compute_attestation.js attested_ach_cleaned.json
import fs from 'fs';
import crypto from 'crypto';

function canonicalJson(obj) {
  return JSON.stringify(obj, Object.keys(obj).sort(), 0);
}
function sha256hex(buf) {
  return crypto.createHash('sha256').update(buf).digest('hex');
}
function merkleRoot(hexHashes) {
  if (hexHashes.length === 0) return [null, []];
  const layers = [hexHashes.slice()];
  let nodes = hexHashes.slice();
  while (nodes.length > 1) {
    const next = [];
    for (let i=0; i<nodes.length; i+=2) {
      const left = nodes[i];
      const right = (i+1 < nodes.length) ? nodes[i+1] : nodes[i];
      const combined = Buffer.concat([Buffer.from(left, 'hex'), Buffer.from(right, 'hex')]);
      next.push(sha256hex(combined));
    }
    layers.push(next);
    nodes = next;
  }
  return [nodes[0], layers];
}

const file = process.argv[2];
if (!file) throw new Error('Usage: node compute_attestation.js file.json');
const obj = JSON.parse(fs.readFileSync(file, 'utf8'));
const payloadCanon = JSON.stringify(obj, Object.keys(obj).sort());
const payloadHash = sha256hex(Buffer.from(payloadCanon, 'utf8'));
const leaves = [];
const leafHashes = [];
for (const k of Object.keys(obj).sort()) {
  const canon = JSON.stringify({[k]: obj[k]}, Object.keys({[k]: obj[k]}).sort());
  const h = sha256hex(Buffer.from(canon, 'utf8'));
  leaves.push({field: k, canonical: canon, hash: h});
  leafHashes.push(h);
}
const [root, layers] = merkleRoot(leafHashes);
const out = { payload_hash: payloadHash, merkle_root: root, leaf_count: leafHashes.length, leaves, layers };
fs.writeFileSync(file.replace('.json', '_attestation.json'), JSON.stringify(out, null, 2));
console.log('payload_hash', payloadHash);
console.log('merkle_root', root);

#!/usr/bin/env python3
"""
nacha_builder.py
Usage:
  - Provide a secrets JSON mapping file (local vault) or implement get_secret(key) to fetch from your vault.
  - python3 nacha_builder.py --template nacha_template.json --x9 x9_ach_settings_vault.json --secrets secrets.json --out ./nacha_COMPLETE.ach
"""
import json, argparse, datetime, sys, re, hashlib

def aba_valid(routing):
    d = re.sub(r'\\D', '', routing)
    if len(d) != 9: return False
    nums = [int(x) for x in d]
    s = 3*(nums[0]+nums[3]+nums[6]) + 7*(nums[1]+nums[4]+nums[7]) + 1*(nums[2]+nums[5]+nums[8])
    return s % 10 == 0

# Simple secret loader: from JSON map (key -> value)
def load_secrets(path):
    if not path: return {}
    with open(path, 'r', encoding='utf-8') as f:
        return json.load(f)

def resolve_vault(ref, secrets):
    # ref like vault://scherer/receiver/account or raw numeric string
    if isinstance(ref, (int, float)): return str(ref)
    if isinstance(ref, str) and ref.startswith("vault://"):
        k = ref.replace("vault://", "")
        return secrets.get(k) or secrets.get(ref) or None
    return ref

def pad(s, width, left=False):
    s = str(s or "")
    if left:
        return s.rjust(width)[:width]
    return s.ljust(width)[:width]

def format_file_header(immediate_dest, immediate_origin, creation_date, creation_time):
    # simplified file header fixed 94 char:
    # 1 Record Type Code (1) + priority(2) + immediate destination(10) + immediate origin(10) + date/time(6+4) ...
    rec = []
    rec.append('1')  # record type
    rec.append('01') # priority
    rec.append(pad(immediate_dest,10))   # immediate destination (10)
    rec.append(pad(immediate_origin,10))  # immediate origin (10)
    rec.append(pad(creation_date,6))
    rec.append(pad(creation_time,4))
    # rest fill
    line = ''.join(rec).ljust(94)[:94]
    return line

def format_batch_header(b):
    # 5 record: service class, company name, company id, sec, company desc, odfi
    r = '5'
    r += pad(str(b.get('service_class_code','200')),3)
    r += pad(b.get('company_name',''),16)
    r += pad(b.get('company_identification',''),10)
    r += pad(b.get('standard_entry_class_code','WEB'),3)
    r += pad(b.get('company_entry_description','PAYROLL'),10)
    r += pad('',25)  # discretionary
    r += pad(b.get('odfi_routing',''),8)
    return r.ljust(94)[:94]

def format_entry_detail(e, trace_seq, odfi_routing):
    # simplified 6 record
    txn_code = str(e.get('transaction_code','22'))
    rdfi = pad(e.get('rdfi',''),9)
    acct = pad(e.get('account',''),17)
    amt = str(int(e.get('amount_cents',0))).rjust(10,'0')
    individ = pad(e.get('individual_identification',''),15)
    name = pad(e.get('individual_name',''),22)
    trace = (odfi_routing[:8] + str(trace_seq).rjust(7,'0'))[:15]
    rec = '6' + txn_code + rdfi[:8] + rdfi[8] + acct + amt + pad('',15) + name + ' 0' + trace
    return rec.ljust(94)[:94], int(amt)

def format_batch_control(entry_count, entry_hash, total_debit, total_credit):
    # 8 record simplified
    r = '8' + pad(str(entry_count),6) + pad(str(entry_hash),10) + pad(str(total_debit).rjust(12,'0'),12) + pad(str(total_credit).rjust(12,'0'),12)
    return r.ljust(94)[:94]

def format_file_control(batch_count, block_count, entry_count, entry_hash, total_debit, total_credit):
    r = '9' + pad(str(batch_count),6) + pad(str(block_count),6) + pad(str(entry_count),8) + pad(str(entry_hash),10) + pad(str(total_debit).rjust(12,'0'),12) + pad(str(total_credit).rjust(12,'0'),12)
    return r.ljust(94)[:94]

def compute_entry_hash(entries):
    # per NACHA: entry hash is sum of routing numbers’ first 8 digits, truncated to 10 digits (this is simplified)
    s = 0
    for ent in entries:
        r = re.sub('\\D','', ent.get('rdfi','') or '')
        s += int(r[:8] or 0)
    return s % (10**10)

def main(args):
    tpl = json.load(open(args.template))
    x9 = json.load(open(args.x9))
    secrets = load_secrets(args.secrets) if args.secrets else {}
    # resolve odfi
    odfi = resolve_vault(x9['Originator'].get('ODFI_Routing_vault_ref'), secrets) or ''
    odfi_acct = resolve_vault(x9['Originator'].get('ODFI_Account_vault_ref'), secrets) or ''
    today = datetime.datetime.utcnow()
    date_yy = today.strftime('%y%m%d')
    time_hh = today.strftime('%H%M')
    fh = format_file_header(immediate_dest=odfi, immediate_origin=odfi_acct, creation_date=date_yy, creation_time=time_hh)
    out_lines = [fh]
    # build batches
    overall_entries = []
    for b in tpl.get('batches', []):
        # resolve odfi for batch if vault ref present
        b['odfi_routing'] = resolve_vault(b.get('odfi_routing_vault_ref') or x9['Originator'].get('ODFI_Routing_vault_ref'), secrets) or odfi
        bh = format_batch_header({**b, 'odfi_routing': b['odfi_routing']})
        out_lines.append(bh)
        trace_seq = 1
        batch_entries = []
        for e in b.get('entries', []):
            # resolve per-entry vault refs
            rdfi = resolve_vault(e.get('routing_vault_ref') or e.get('routing') , secrets) or ''
            acct = resolve_vault(e.get('account_vault_ref') or e.get('account') , secrets) or ''
            detail, amt = format_entry_detail({'transaction_code': e.get('transaction_code',22), 'rdfi': rdfi, 'account': acct, 'amount_cents': e.get('amount_cents',0), 'individual_identification': e.get('individual_identification',''), 'individual_name': e.get('individual_name','')}, trace_seq, b['odfi_routing'])
            out_lines.append(detail)
            batch_entries.append({'rdfi': rdfi, 'amount': amt})
            overall_entries.append({'rdfi': rdfi, 'amount': amt})
            trace_seq += 1
        # batch control compute
        entry_count = len(batch_entries)
        entry_hash = compute_entry_hash(batch_entries)
        total_credit = sum(int(x['amount']) for x in batch_entries)
        total_debit = 0
        bc = format_batch_control(entry_count, entry_hash, total_debit, total_credit)
        out_lines.append(bc)
    # file control
    batch_count = len(tpl.get('batches', []))
    # block_count: NACHA files are multiple of 10 lines (blocks of 10). We'll compute final block_count
    lines = len(out_lines)
    block_count = (lines + 2 + 9) // 10  # +2 for file control lines that'll be added; round up
    entry_count_total = sum(1 for _ in overall_entries)
    entry_hash_total = compute_entry_hash(overall_entries)
    total_credit = sum(int(x['amount']) for x in overall_entries)
    total_debit = 0
    fc = format_file_control(batch_count, block_count, entry_count_total, entry_hash_total, total_debit, total_credit)
    out_lines.append(fc)
    # pad to multiple of 10 lines with '9' records per NACHA spec
    while len(out_lines) % 10 != 0:
        out_lines.append('9'.ljust(94))
    out_path = args.out or f"nacha_COMPLETE_{date_yy}.ach"
    with open(out_path, 'w', encoding='utf-8') as f:
        for r in out_lines:
            f.write(r + '\\n')
    print("Wrote NACHA:", out_path)
    # basic validations
    for e in overall_entries:
        if not aba_valid(e['rdfi']):
            print("WARNING: invalid ABA routing checksum for", e['rdfi'])
    print("Entry count:", entry_count_total, "Entry hash:", entry_hash_total, "Total credit cents:", total_credit)

if __name__ == '__main__':
    p = argparse.ArgumentParser()
    p.add_argument('--template', required=True)
    p.add_argument('--x9', required=True)
    p.add_argument('--secrets', required=False, help='JSON file mapping vault paths to values')
    p.add_argument('--out', required=False)
    args = p.parse_args()
    main(args)