#!/usr/bin/env python3
"""Independently build PCAPNG sections and verify CLI provenance and redaction."""
from test_support import default_binary
import argparse
import csv
import datetime
import hashlib
import json
import pathlib
import struct
import subprocess
import tempfile

base = pathlib.Path(__file__).resolve().parents[1]
parser = argparse.ArgumentParser()
parser.add_argument('--binary', type=pathlib.Path, default=default_binary())
options = parser.parse_args()
exe = str(options.binary.resolve())


def block(order, kind, body):
    assert len(body) % 4 == 0
    size = 12 + len(body)
    return struct.pack(order + 'II', kind, size) + body + struct.pack(order + 'I', size)


def option(order, code, value):
    return struct.pack(order + 'HH', code, len(value)) + value + bytes(-len(value) % 4)


def section(order):
    return block(order, 0x0A0D0D0A, struct.pack(order + 'IHHq', 0x1A2B3C4D, 1, 0, -1))


def interface(order, link, resolution=6, offset=0):
    return block(order, 1, struct.pack(order + 'HHI', link, 0, 0)
                 + option(order, 9, bytes([resolution]))
                 + option(order, 14, struct.pack(order + 'q', offset))
                 + option(order, 2, b'INTERFACE_NAME_NOT_EXPORTED')
                 + option(order, 0, b''))


def packet(order, iface, ticks, frame):
    return block(order, 6, struct.pack(order + 'IIIII', iface, ticks >> 32,
                                     ticks & 0xffffffff, len(frame), len(frame))
                 + frame + bytes(-len(frame) % 4)
                 + option(order, 1, b'PACKET_COMMENT_NOT_EXPORTED'))


def ip_packet():
    payload = b'PAYLOAD_NOT_EXPORTED'
    udp = struct.pack('!HHHH', 40000, 53, 8 + len(payload), 0) + payload
    header = struct.pack('!BBHHHBBH4s4s', 0x45, 0, 20 + len(udp), 0, 0, 64, 17, 0,
                         bytes([192, 0, 2, 77]), bytes([198, 51, 100, 8]))
    checksum = sum(struct.unpack('!10H', header))
    while checksum >> 16:
        checksum = (checksum & 65535) + (checksum >> 16)
    header = header[:10] + struct.pack('!H', (~checksum) & 65535) + header[12:]
    return header + udp


ip = ip_packet()
sll = struct.pack('!HHH8sH', 0, 1, 6, bytes(8), 0x800) + ip
sll2 = struct.pack('!HHIHBB8s', 0x800, 0, 7, 1, 0, 6, bytes(8)) + ip
capture = bytearray(section('<') + interface('<', 113) + interface('<', 276, 9, -10))
expected = []


def add_packet(order, section_id, iface, ticks, scale, offset, frame):
    expected.append((len(capture), order, section_id, iface, ticks, scale, offset, len(frame)))
    capture.extend(packet(order, iface, ticks, frame))


add_packet('<', 1, 0, 1600000000123456, 10**6, 0, sll)
add_packet('<', 1, 1, 1600000010123456789, 10**9, -10, sll2)
add_packet('<', 1, 0, 1600000001123456, 10**6, 0, sll)
capture.extend(section('>') + interface('>', 101, 128 | 10))
add_packet('>', 2, 0, 1600000000 * 1024 + 57, 1024, 0, ip)
capture.extend(block('>', 3, struct.pack('>I', len(ip)) + ip + bytes(-len(ip) % 4)))
metadata = b'SECRET_METADATA_NOT_EXPORTED'
capture.extend(block('>', 0x0000000A, struct.pack('>II', 0x544c534b, len(metadata))
                     + metadata + bytes(-len(metadata) % 4)))
capture.extend(interface('>', 999))
capture.extend(packet('>', 1, 1600000000000000, ip))
# Preserve preceding records while identifying malformed trailing framing.
broken = capture + struct.pack('>II', 6, 0xffffffff)

with tempfile.TemporaryDirectory(prefix='k957-pcapng-') as directory:
    root = pathlib.Path(directory)
    source = root / 'source'
    source.mkdir()
    (source / 'traffic.bin').write_bytes(capture)  # Exercise magic detection.
    (source / 'broken.pcapng').write_bytes(broken)
    (source / 'observer.jsonl').write_text(
        '{"timestamp":"2020-09-13T12:26:40Z","src_ip":"192.0.2.77"}\n', encoding="utf-8")

    def run(*args):
        return subprocess.run([exe, *map(str, args)], text=True, capture_output=True, check=True, encoding="utf-8")

    package = root / 'case.k957'
    run('collect', '--root', source, '--out', package, '--case', 'PCAPNG',
        '--operator', 'Tester', '--scope', 'Synthetic')
    before = hashlib.sha256(package.read_bytes()).hexdigest()
    run('analyze', '--in', package, '--out', root / 'report')
    analysis = json.loads((root / 'report/analysis.json').read_text(encoding="utf-8"))
    summaries = {pathlib.Path(s['source']).name: s for s in analysis['capture_summaries']}
    summary = summaries['traffic.bin']
    assert (summary['records'], summary['parsed'], summary['skipped']) == (6, 4, 2)
    assert summary['sections'] == 2 and summary['byte_order'] == 'mixed'
    assert len(summary['interfaces']) == 4 and summary['ignored_blocks'] == 1
    assert summary['skip_reasons'] == {'missing_timestamp': 1, 'unsupported_link_type': 1}
    assert not summary.get('error') and summaries['broken.pcapng']['error']
    assert summaries['broken.pcapng']['parsed'] == 4
    events = sorted((e for e in analysis['timeline'] if e['type'] == 'pcap_packet'
                     and e['source'].endswith('traffic.bin')), key=lambda e: e['packet'])
    for event, (position, order, section_id, iface, ticks, scale, offset, size) in zip(events, expected, strict=True):
        block_type, block_size = struct.unpack_from(order + 'II', capture, position)
        interface_id, high, low, caplen, original = struct.unpack_from(order + 'IIIII', capture, position + 8)
        assert block_type == 6 and struct.unpack_from(order + 'I', capture, position + block_size - 4)[0] == block_size
        assert (high << 32 | low) == ticks and interface_id == iface
        seconds, fraction = divmod(ticks, scale)
        nanoseconds = fraction * 10**9 // scale
        stamp = datetime.datetime.fromtimestamp(seconds + offset, datetime.timezone.utc).strftime('%Y-%m-%dT%H:%M:%S')
        stamp += (f'.{nanoseconds:09d}'.rstrip('0') if nanoseconds else '') + 'Z'
        assert event['time'] == stamp and event['byte_offset'] == position
        assert event['section'] == section_id and event.get('interface_id', 0) == iface
        assert event['captured_length'] == caplen == size and event['original_length'] == original
    flows = [f for f in analysis['network_flows'] if f['source'].endswith('traffic.bin')]
    assert len(flows) == 3 and sorted(f['packets'] for f in flows) == [1, 1, 2]
    assert {(f['section'], f.get('interface_id', 0)) for f in flows} == {(1, 0), (1, 1), (2, 0)}
    assert any(c['value'] == '192.0.2.77' and c['sources'] == 3 for c in analysis['correlations'])
    for correlation in analysis['correlations']:
        for ref in correlation['references']:
            if ref.get('packet'):
                assert ref['section'] in (1, 2)
    for name in ('network.csv', 'timeline.csv'):
        with (root / 'report' / name).open(encoding="utf-8") as file:
            rows = list(csv.DictReader(file))
        assert any(row['section'] == '2' and row['interface_id'] == '0' for row in rows)
    assert 'Bölüm 2 / Arayüz 0' in (root / 'report/report.html').read_text(encoding="utf-8")
    run('share', '--in', package, '--out', root / 'shared')
    shared = json.loads((root / 'shared/shared.json').read_text(encoding="utf-8"))
    assert len(shared['network_flows']) == 6
    assert all('first' not in f and f['section'] in (1, 2) for f in shared['network_flows'])
    assert all(c['interface_count'] == 4 and c['ignored_blocks'] == 1 for c in shared['capture_summaries'])
    for report in ('report', 'shared'):
        for file in (root / report).iterdir():
            contents = file.read_text(encoding="utf-8")
            for value in ('INTERFACE_NAME_NOT_EXPORTED', 'PACKET_COMMENT_NOT_EXPORTED',
                          'PAYLOAD_NOT_EXPORTED', 'SECRET_METADATA_NOT_EXPORTED'):
                assert value not in contents, (file.name, value)
            if report == 'shared':
                for value in ('192.0.2.77', '198.51.100.8', 'traffic.bin', 'broken.pcapng', '2020-09-13'):
                    assert value not in contents, (file.name, value)
    assert hashlib.sha256(package.read_bytes()).hexdigest() == before
    print('PASS: PCAPNG mixed sections, four interfaces, SLL/SLL2, independent timestamps/offsets, '
          'interface-separated flows, malformed-tail accounting, skipped blocks, correlation, '
          'HTML/CSV provenance, masked exports, metadata omission, unchanged evidence')
