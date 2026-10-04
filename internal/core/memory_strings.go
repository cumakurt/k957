package core

// Printable strings are stored in segments, keeping scanner RAM independent of
// string/image length. Adjacent addresses and continuation flags reconstruct
// a long string without discarding bytes. Secret text stays in private sidecars.
const memoryStringSegment = 64 << 10

type memoryStringState struct {
	start     uint64
	bytes     []byte
	continued bool
}

func (s *memScan) stringByte(state *memoryStringState, at uint64, b byte, encoding string) {
	if b >= 32 && b < 127 {
		if len(state.bytes) == 0 {
			state.start = at
		}
		state.bytes = append(state.bytes, b)
		if len(state.bytes) >= memoryStringSegment {
			s.flushString(state, encoding, true)
		}
	} else {
		s.flushString(state, encoding, false)
	}
}
func (s *memScan) flushString(state *memoryStringState, encoding string, continuing bool) {
	if len(state.bytes) >= 4 || state.continued && len(state.bytes) > 0 {
		s.emit(MemoryResult{Kind: "string", Physical: state.start, Encoding: encoding, Detail: string(state.bytes), Continuation: state.continued, Continues: continuing})
		s.resultWriter.result.Strings++
	}
	state.bytes = state.bytes[:0]
	state.continued = continuing
}
func (s *memScan) scanStrings(base uint64, p []byte) {
	if s.resultWriter == nil {
		return
	}
	for i, b := range p {
		at := base + uint64(i)
		s.stringByte(&s.asciiString, at, b, "ascii")
		s.urlByte(&s.asciiURL, at, b, "ascii")
		if s.hasPreviousByte {
			parity := (at - 1) % 2
			ch := byte(0)
			if b == 0 {
				ch = s.previousByte
			}
			s.stringByte(&s.utf16Strings[parity], at-1, ch, "utf-16le")
			s.urlByte(&s.utf16URLs[parity], at-1, ch, "utf-16le")
		}
		s.previousByte = b
		s.hasPreviousByte = true
	}
}
func (s *memScan) finishStrings() {
	if s.resultWriter == nil {
		return
	}
	s.finishURLs()
	s.flushString(&s.asciiString, "ascii", false)
	for i := range s.utf16Strings {
		s.flushString(&s.utf16Strings[i], "utf-16le", false)
	}
	s.hasPreviousByte = false
}
