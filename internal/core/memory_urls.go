package core

// URL tokens use bounded segments, like strings. Neither image windows nor
// report preview length truncate the complete address-scoped result stream.
type memoryURLState struct {
	prefix       [8]byte
	prefixN      int
	start        uint64
	bytes        []byte
	active       bool
	continued    bool
	schemeLength int
}

func (s *memScan) urlByte(state *memoryURLState, at uint64, b byte, encoding string) {
	if state.active {
		if b <= 32 || b >= 127 || b == '"' || b == '\'' || b == '<' || b == '>' {
			s.flushURL(state, encoding, false)
			state.active = false
			state.prefixN = 0
			return
		}
		if len(state.bytes) == 0 {
			state.start = at
		}
		state.bytes = append(state.bytes, b)
		if len(state.bytes) >= memoryStringSegment {
			s.flushURL(state, encoding, true)
		}
		return
	}
	if b <= 32 || b >= 127 {
		state.prefixN = 0
		return
	}
	if state.prefixN == len(state.prefix) {
		copy(state.prefix[:], state.prefix[1:])
		state.prefixN--
	}
	state.prefix[state.prefixN] = b
	state.prefixN++
	if b != '/' {
		return
	}
	scheme := ""
	for _, candidate := range []string{"https://", "http://"} {
		if state.prefixN < len(candidate) {
			continue
		}
		match := true
		for i, want := range []byte(candidate) {
			got := state.prefix[state.prefixN-len(candidate)+i]
			if got >= 'A' && got <= 'Z' {
				got += 'a' - 'A'
			}
			if got != want {
				match = false
				break
			}
		}
		if match {
			scheme = candidate
			break
		}
	}
	if scheme == "" {
		return
	}
	width := uint64(1)
	if encoding == "utf-16le" {
		width = 2
	}
	state.start = at - uint64(len(scheme)-1)*width
	state.bytes = append(state.bytes[:0], state.prefix[state.prefixN-len(scheme):state.prefixN]...)
	state.schemeLength = len(scheme)
	state.active = true
	state.prefixN = 0
}
func (s *memScan) flushURL(state *memoryURLState, encoding string, more bool) {
	if len(state.bytes) > state.schemeLength+3 || state.continued && len(state.bytes) > 0 {
		s.emit(MemoryResult{Kind: "url", Physical: state.start, Encoding: encoding, Detail: string(state.bytes), Continuation: state.continued, Continues: more})
		if !state.continued {
			s.resultWriter.result.URLs++
			preview := string(state.bytes[:min(200, len(state.bytes))])
			if len(s.urls) < memoryURLLimit && !s.urlSeen[preview] {
				s.urls = append(s.urls, preview)
				s.urlSeen[preview] = true
			}
		}
	}
	state.bytes = state.bytes[:0]
	state.continued = more
}
func (s *memScan) finishURLs() {
	s.flushURL(&s.asciiURL, "ascii", false)
	s.asciiURL = memoryURLState{}
	for i := range s.utf16URLs {
		s.flushURL(&s.utf16URLs[i], "utf-16le", false)
		s.utf16URLs[i] = memoryURLState{}
	}
}
