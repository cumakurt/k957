#!/usr/bin/env python3
"""Build synthetic PCAP with Python struct; independently check Go summaries.
Use --examples DIR to also save the synthetic input files for packaged examples.
"""
from test_support import default_binary
import argparse
import csv
import datetime
import hashlib
import ipaddress
import json
import pathlib
import struct
import subprocess
import tempfile

base = pathlib.Path(__file__).resolve().parents[1]
exe = str(default_binary())
args = argparse.ArgumentParser()
args.add_argument('--examples', type=pathlib.Path)
options = args.parse_args()

def checksum(data):
    if len(data) % 2:
        data += b'\0'
    total = sum(struct.unpack('!' + 'H' * (len(data)//2), data))
    while total >> 16:
        total = (total & 65535) + (total >> 16)
    return (~total) & 65535

def ip4(tcp=False, reverse=False, fragment=False):
    src, dst = ipaddress.ip_address('192.0.2.77').packed, ipaddress.ip_address('198.51.100.8').packed
    sport, dport = 40000, 443 if tcp else 53
    if reverse:
        src, dst, sport, dport = dst, src, dport, sport
    payload = b'PAYLOAD_DO_NOT_EXPORT'
    proto = 6 if tcp else 17
    if tcp:
        transport = struct.pack('!HHIIBBHHH', sport, dport, 1, 0, 0x50, 2, 65535, 0, 0) + payload
        checkpos = 16
    else:
        transport = struct.pack('!HHHH', sport, dport, 8 + len(payload), 0) + payload
        checkpos = 6
    pseudo = src + dst + struct.pack('!BBH', 0, proto, len(transport))
    check = checksum(pseudo + transport) or 65535
    transport = transport[:checkpos] + struct.pack('!H', check) + transport[checkpos+2:]
    header = struct.pack('!BBHHHBBH4s4s', 0x45, 0, 20+len(transport), 123, 0x2000 if fragment else 0, 64, proto, 0, src, dst)
    header = header[:10] + struct.pack('!H', checksum(header)) + header[12:]
    assert checksum(header) == 0
    return header + transport

def ip6():
    src = ipaddress.ip_address('2001:db8::77').packed
    dst = ipaddress.ip_address('2001:db8::88').packed
    tcp = struct.pack('!HHIIBBHHH', 50000, 443, 1, 0, 0x50, 2, 65535, 0, 0)
    pseudo = src + dst + struct.pack('!I3xB', len(tcp), 6)
    tcp = tcp[:16] + struct.pack('!H', checksum(pseudo + tcp)) + tcp[18:]
    hop = bytes([6, 0, 0, 0, 0, 0, 0, 0])
    return struct.pack('!IHBB16s16s', 6 << 28, len(hop)+len(tcp), 0, 64, src, dst) + hop + tcp

def ethernet(packet, vlan=False):
    typ = 0x86dd if packet[0] >> 4 == 6 else 0x0800
    return bytes(12) + (struct.pack('!HHHHH', 0x88a8, 100, 0x8100, 200, typ) if vlan else struct.pack('!H', typ)) + packet

def capture(records, endian='<', nano=False, link=1):
    output = bytearray(struct.pack(endian+'IHHIIII', 0xa1b23c4d if nano else 0xa1b2c3d4, 2, 4, 0, 0, 65535, link))
    offsets = []
    for i, (frame, original, fraction) in enumerate(records):
        offsets.append(len(output))
        output += struct.pack(endian+'IIII', 1600000000+i, fraction, len(frame), original) + frame
    return bytes(output), offsets

udp = ethernet(ip4(), True)
tcp_full = ethernet(ip4(tcp=True))
truncated = tcp_full[:-len(b'PAYLOAD_DO_NOT_EXPORT')]
malformed = bytearray(ethernet(ip4()))
malformed[16:18] = struct.pack('!H', 4)
frames = [udp, udp, ethernet(ip4(reverse=True)), ethernet(ip6()), ethernet(ip4(fragment=True)),
          bytes(12)+b'\x08\x06'+bytes(28), truncated, bytes(malformed), udp]
records = [(frame, len(tcp_full) if i == 6 else len(frame), 1000000 if i == 8 else 123456) for i, frame in enumerate(frames)]
main, offsets = capture(records)
nano, _ = capture([(ip4(), len(ip4()), 123456789)], '>', True, 101)
fixtures = {'traffic.pcap': main, 'big-nano.bin': nano, 'unsupported.pcapng': bytes([10, 13, 13, 10]),
            'observer.jsonl': b'{"timestamp":"2020-09-13T12:26:40Z","src_ip":"192.0.2.77","message":"synthetic observer"}\n'}
if options.examples:
    options.examples.mkdir(parents=True, exist_ok=False)
    for name, contents in fixtures.items():
        (options.examples / name).write_bytes(contents)

with tempfile.TemporaryDirectory() as directory:
    p = pathlib.Path(directory)
    source = p / 'source'
    source.mkdir()
    for name, contents in fixtures.items():
        (source / name).write_bytes(contents)
    def run(*args):
        return subprocess.run([exe, *map(str, args)], capture_output=True, text=True, check=True, encoding="utf-8")
    rules = p / 'rules.json'
    rules.write_text('[{"id":"payload","contains":"PAYLOAD_DO_NOT_EXPORT"}]', encoding="utf-8")
    package = p / 'case.k957'
    run('collect', '--root', source, '--out', package, '--case', 'PCAP', '--operator', 'Tester', '--scope', 'Synthetic')
    before = hashlib.sha256(package.read_bytes()).hexdigest()
    run('analyze', '--in', package, '--out', p / 'report', '--rules', rules)
    a = json.loads((p / 'report/analysis.json').read_text(encoding="utf-8"))
    summary = next(s for s in a['capture_summaries'] if s['source'].endswith('traffic.pcap'))
    assert (summary['records'], summary['parsed'], summary['skipped'], summary['truncated_packets']) == (9, 5, 4, 1)
    assert summary['skip_reasons'] == {'fragment': 1, 'unsupported_link_protocol': 1, 'invalid_ip_length': 1, 'invalid_timestamp': 1}
    flow = next(f for f in a['network_flows'] if f['source'].endswith('traffic.pcap') and f['source_ip'] == '192.0.2.77' and f['protocol'] == 'UDP')
    assert flow['packets'] == 2 and flow['captured_bytes'] == 2 * len(udp)
    assert [r['byte_offset'] for r in flow['references']] == offsets[:2]
    assert [r['packet'] for r in flow['references']] == [1, 2]
    # Read reference bytes independently, without the Go parser.
    for ref in flow['references']:
        sec, fraction, caplen, original = struct.unpack_from('<IIII', main, ref['byte_offset'])
        expected = datetime.datetime.fromtimestamp(sec, datetime.timezone.utc).strftime('%Y-%m-%dT%H:%M:%S') + f'.{fraction:06d}Z'
        assert ref['time'] == expected and ref['captured_length'] == caplen and ref['original_length'] == original
    ev = next(e for e in a['timeline'] if e['type'] == 'pcap_packet' and e['source'].endswith('big-nano.bin'))
    assert ev['time'] == '2020-09-13T12:26:40.123456789Z' and ev['source_port'] == 40000
    assert len(a['network_flows']) == 5 and not a['findings']
    assert any(c['kind'] == 'ip' and c['value'] == '192.0.2.77' and c['sources'] == 3 for c in a['correlations'])
    assert any(s['format'] == 'PCAPNG' and s.get('error') for s in a['capture_summaries'])
    with (p / 'report/network.csv').open(encoding="utf-8") as f:
        assert len(list(csv.DictReader(f))) == 5
    for f in (p / 'report').iterdir():
        assert 'PAYLOAD_DO_NOT_EXPORT' not in f.read_text(encoding="utf-8") or f.name == 'analysis.json'  # The rule definition itself is included in the full analysis.
    run('share', '--in', package, '--out', p / 'shared', '--rules', rules)
    shared = json.loads((p / 'shared/shared.json').read_text(encoding="utf-8"))
    assert len(shared['network_flows']) == 5 and len(shared['capture_summaries']) == 3
    for f in (p / 'shared').iterdir():
        assert all(value not in f.read_text(encoding="utf-8") for value in ('192.0.2.77', '198.51.100.8', '2001:db8::77', '2001:db8::88', 'traffic.pcap', '2020-09-13', 'PAYLOAD_DO_NOT_EXPORT')), f.name
    assert hashlib.sha256(package.read_bytes()).hexdigest() == before
    print('PASS: independent PCAP records/offsets/byte counts/UTC, four directional flows plus raw-IP capture, IPv6 TCP extension, truncation and four skip reasons, truncated PCAPNG rejection, cross-log IP correlation, no payload findings, masked network exports, unchanged package')
