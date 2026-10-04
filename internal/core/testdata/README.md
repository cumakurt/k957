# Native artifact fixtures

Security_1_record.evtx is a public reference fixture from Velocidex/evtx, commit 0ef2ce4e83a8dd5a403d9f2e748096f9ead0bd1e (Apache-2.0). Original: https://github.com/Velocidex/evtx/blob/0ef2ce4e83a8dd5a403d9f2e748096f9ead0bd1e/testdata/Security_1_record.evtx

SHA-256: 4b4ee9fbbf33f8a67516f03b67cb6d888da574d66aa2120d6caf44223d15cfd7

The file contains one event: ID 1102, XML System record 33072, host TestComputer. The binary record header contains ID 33072 and FILETIME 131942055246727578 at byte offset 4608. Header and XML System values are retained separately. Timeline time uses the binary header FILETIME; the XML System time is retained in native.other_times. This fixture validates decoding, not native Windows collection compatibility.
