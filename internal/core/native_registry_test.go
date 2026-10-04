package core

import (
	"context"
	"encoding/binary"
	"os"
	"path/filepath"
	"testing"
)

func registryFixture() []byte {
	b := make([]byte, 8192)
	copy(b, "regf")
	put := binary.LittleEndian.PutUint32
	for off, v := range map[int]uint32{4: 1, 8: 1, 20: 1, 24: 5, 32: 1, 36: 32, 40: 4096, 44: 1} {
		put(b[off:], v)
	}
	copy(b[4096:], "hbin")
	put(b[4104:], 4096)
	cursor := 32
	cell := func(payload []byte) uint32 {
		off := cursor
		size := (len(payload) + 4 + 7) &^ 7
		put(b[4096+off:], uint32(-int32(size)))
		copy(b[4100+off:], payload)
		cursor += size
		return uint32(off)
	}
	nk := make([]byte, 80)
	copy(nk, "nk")
	binary.LittleEndian.PutUint16(nk[2:], 0x2c)
	binary.LittleEndian.PutUint64(nk[4:], 133485408001234567)
	put(nk[16:], 0xffffffff)
	put(nk[28:], 0xffffffff)
	put(nk[32:], 0xffffffff)
	put(nk[36:], 1)
	binary.LittleEndian.PutUint16(nk[72:], 4)
	copy(nk[76:], "TEST")
	root := cell(nk)
	vk := make([]byte, 23)
	copy(vk, "vk")
	binary.LittleEndian.PutUint16(vk[2:], 3)
	put(vk[4:], 20)
	put(vk[12:], 1)
	binary.LittleEndian.PutUint16(vk[16:], 1)
	copy(vk[20:], "Run")
	value := cell(vk)
	refs := make([]byte, 4)
	put(refs, value)
	list := cell(refs)
	raw := make([]byte, 20)
	for i, v := range []byte("synthetic") {
		raw[i*2] = v
	}
	data := cell(raw)
	put(b[4100+int(root)+40:], list)
	put(b[4100+int(value)+8:], data)
	put(b[4096+cursor:], uint32(4096-cursor))
	registryFixtureChecksum(b)
	return b
}
func registryFixtureChecksum(b []byte) {
	var checksum uint32
	for i := 0; i < 508; i += 4 {
		checksum ^= binary.LittleEndian.Uint32(b[i:])
	}
	if checksum == 0 {
		checksum = 1
	}
	if checksum == 0xffffffff {
		checksum = 0xfffffffe
	}
	binary.LittleEndian.PutUint32(b[508:], checksum)
}
func TestRegistryReferencesPrecisionAndBounds(t *testing.T) {
	b := registryFixture()
	path := filepath.Join(t.TempDir(), "fixture.hive")
	if err := os.WriteFile(path, b, 0600); err != nil {
		t.Fatal(err)
	}
	events, s, err := parseRegistry(context.Background(), path, Item{ID: "E1"}, 10)
	if err != nil || len(events) != 1 || s.Parsed != 1 {
		t.Fatalf("%+v %v", s, err)
	}
	event := events[0]
	if event.Time.Format("2006-01-02T15:04:05.999999999Z07:00") != "2024-01-01T00:00:00.1234567Z" || event.ByteOffset != 4132 || event.Registry.Key != "TEST" || len(event.Registry.Values) != 1 || event.Registry.Values[0].Text != "synthetic" {
		t.Fatalf("incorrect registry projection: %s", JSON(event))
	}
	_, s, err = parseRegistry(context.Background(), path, Item{ID: "E1"}, 0)
	if err != nil || !s.Limited || s.Parsed != 0 || s.Skipped != 1 {
		t.Fatalf("budget ignored: %+v %v", s, err)
	}
	for _, mutate := range []func([]byte){func(v []byte) { v[508] ^= 1 }, func(v []byte) { v[8] = 2; registryFixtureChecksum(v) }, func(v []byte) { binary.LittleEndian.PutUint32(v[4128:], 0x80000000) }} {
		bad := append([]byte(nil), b...)
		mutate(bad)
		if err = os.WriteFile(path, bad, 0600); err != nil {
			t.Fatal(err)
		}
		if _, _, err = parseRegistry(context.Background(), path, Item{}, 10); err == nil {
			t.Fatal("corrupt hive accepted")
		}
	}
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	if _, err = registryCells(ctx, b); err == nil {
		t.Fatal("cancel ignored")
	}
}
func TestRegistryIndexCyclesAndUnicode(t *testing.T) {
	ri := []byte{'r', 'i', 1, 0, 0, 0, 0, 0}
	binary.LittleEndian.PutUint32(ri[4:], 12)
	if _, err := registrySubkeys(map[uint32][]byte{12: ri}, 12, 1); err == nil {
		t.Fatal("index cycle accepted")
	}
	if _, err := registryName([]byte{0, 0xd8}, false); err == nil {
		t.Fatal("unpaired surrogate accepted")
	}
	if s, err := registryName([]byte{0xe9}, true); err != nil || s != "é" {
		t.Fatal("compressed registry character lost", s, err)
	}
}
