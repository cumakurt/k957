package core

import (
	"encoding/binary"
	"fmt"
	"net/netip"
	"strings"
)

func dnsName(payload []byte, start int) (string, int, error) {
	if start >= len(payload) {
		return "", 0, protocolError()
	}
	labels := []string{}
	position := start
	next := -1
	wireBytes := 0
	seen := map[int]bool{}
	for count := 0; count < 128; count++ {
		if position >= len(payload) || seen[position] {
			return "", 0, protocolError()
		}
		seen[position] = true
		length := int(payload[position])
		position++
		if length == 0 {
			if next < 0 {
				next = position
			}
			return strings.Join(labels, "."), next, nil
		}
		if length&0xc0 == 0xc0 {
			if position >= len(payload) {
				return "", 0, protocolError()
			}
			target := (length&0x3f)<<8 | int(payload[position])
			if target >= position-1 {
				return "", 0, protocolError()
			}
			if next < 0 {
				next = position + 1
			}
			position = target
			continue
		}
		if length > 63 || position+length > len(payload) {
			return "", 0, protocolError()
		}
		wireBytes += length + 1
		if wireBytes > 255 {
			return "", 0, protocolError()
		}
		var label strings.Builder
		for _, b := range payload[position : position+length] {
			if b < 33 || b > 126 || b == '.' || b == '\\' {
				fmt.Fprintf(&label, "\\%03d", b)
			} else {
				label.WriteByte(b)
			}
		}
		labels = append(labels, label.String())
		position += length
	}
	return "", 0, protocolError()
}

func parseDNS(payload []byte) (*DNSMetadata, error) {
	if len(payload) < 12 || len(payload) > 65535 {
		return nil, protocolError()
	}
	flags := binary.BigEndian.Uint16(payload[2:4])
	if flags&0x7800 != 0 {
		return nil, protocolError()
	}
	counts := [4]int{}
	total := 0
	for i := range counts {
		counts[i] = int(binary.BigEndian.Uint16(payload[4+i*2 : 6+i*2]))
		total += counts[i]
	}
	if counts[0] > 16 || total > 128 {
		return nil, protocolError()
	}
	m := &DNSMetadata{ID: binary.BigEndian.Uint16(payload[:2]), Response: flags&0x8000 != 0, RCode: uint8(flags & 15), Questions: []DNSQuestion{}, Omitted: flags&0x200 != 0}
	position := 12
	for n := 0; n < counts[0]; n++ {
		name, next, e := dnsName(payload, position)
		if e != nil || next+4 > len(payload) {
			return nil, protocolError()
		}
		m.Questions = append(m.Questions, DNSQuestion{Name: name, Type: binary.BigEndian.Uint16(payload[next : next+2]), Class: binary.BigEndian.Uint16(payload[next+2 : next+4])})
		position = next + 4
	}
	for section := 1; section < 4; section++ {
		for n := 0; n < counts[section]; n++ {
			name, next, e := dnsName(payload, position)
			if e != nil || next+10 > len(payload) {
				return nil, protocolError()
			}
			typ, class := binary.BigEndian.Uint16(payload[next:next+2]), binary.BigEndian.Uint16(payload[next+2:next+4])
			size := int(binary.BigEndian.Uint16(payload[next+8 : next+10]))
			position = next + 10
			end := position + size
			if end > len(payload) {
				return nil, protocolError()
			}
			value := ""
			if section == 1 && class == 1 {
				switch typ {
				case 1:
					if size != 4 {
						return nil, protocolError()
					}
					value = netip.AddrFrom4([4]byte(payload[position:end])).String()
				case 28:
					if size != 16 {
						return nil, protocolError()
					}
					value = netip.AddrFrom16([16]byte(payload[position:end])).String()
				case 5:
					var after int
					value, after, e = dnsName(payload, position)
					if e != nil || after > end {
						return nil, protocolError()
					}
				}
			}
			if value != "" {
				m.Answers = append(m.Answers, DNSAnswer{Name: name, Type: typ, Value: value})
			} else {
				m.Omitted = true
			}
			position = end
		}
	}
	if position != len(payload) {
		return nil, protocolError()
	}
	return m, nil
}

func parseTLSClientHello(payload []byte) (*TLSMetadata, error) {
	handshake := []byte{}
	for record := 0; record < 8 && len(payload) >= 5; record++ {
		if payload[0] != 22 || payload[1] != 3 {
			return nil, protocolError()
		}
		size := int(binary.BigEndian.Uint16(payload[3:5]))
		if size == 0 || size > 16384 || len(payload) < 5+size {
			return nil, protocolError()
		}
		handshake = append(handshake, payload[5:5+size]...)
		payload = payload[5+size:]
		if len(handshake) >= 4 {
			size := int(handshake[1])<<16 | int(handshake[2])<<8 | int(handshake[3])
			if size > networkStreamLimit {
				return nil, protocolError()
			}
			if len(handshake) >= size+4 {
				handshake = handshake[:size+4]
				break
			}
		}
	}
	if len(handshake) < 4 || handshake[0] != 1 {
		return nil, protocolError()
	}
	size := int(handshake[1])<<16 | int(handshake[2])<<8 | int(handshake[3])
	if size != len(handshake)-4 {
		return nil, protocolError()
	}
	body := handshake[4:]
	if len(body) < 35 {
		return nil, protocolError()
	}
	m := &TLSMetadata{LegacyVersion: binary.BigEndian.Uint16(body[:2])}
	position := 34
	session := int(body[position])
	position++
	if session > 32 || position+session+2 > len(body) {
		return nil, protocolError()
	}
	position += session
	ciphers := int(binary.BigEndian.Uint16(body[position : position+2]))
	position += 2
	if ciphers < 2 || ciphers%2 != 0 || position+ciphers+1 > len(body) {
		return nil, protocolError()
	}
	position += ciphers
	compression := int(body[position])
	position++
	if compression < 1 || position+compression > len(body) {
		return nil, protocolError()
	}
	position += compression
	if position == len(body) {
		return m, nil
	}
	if position+2 > len(body) {
		return nil, protocolError()
	}
	extensions := int(binary.BigEndian.Uint16(body[position : position+2]))
	position += 2
	if position+extensions != len(body) {
		return nil, protocolError()
	}
	seen := map[uint16]bool{}
	for position < len(body) {
		if position+4 > len(body) {
			return nil, protocolError()
		}
		typ := binary.BigEndian.Uint16(body[position : position+2])
		length := int(binary.BigEndian.Uint16(body[position+2 : position+4]))
		position += 4
		if position+length > len(body) || seen[typ] {
			return nil, protocolError()
		}
		seen[typ] = true
		value := body[position : position+length]
		position += length
		switch typ {
		case 0:
			if len(value) < 2 || int(binary.BigEndian.Uint16(value[:2])) != len(value)-2 {
				return nil, protocolError()
			}
			value = value[2:]
			names := 0
			for len(value) > 0 {
				if len(value) < 3 {
					return nil, protocolError()
				}
				kind := value[0]
				size := int(binary.BigEndian.Uint16(value[1:3]))
				value = value[3:]
				if size == 0 || size > len(value) {
					return nil, protocolError()
				}
				if kind == 0 {
					names++
					if names > 1 || !validProtocolText(string(value[:size])) || size > 253 {
						return nil, protocolError()
					}
					m.ServerName = string(value[:size])
				}
				value = value[size:]
			}
		case 16:
			if len(value) < 2 || int(binary.BigEndian.Uint16(value[:2])) != len(value)-2 {
				return nil, protocolError()
			}
			value = value[2:]
			for len(value) > 0 {
				size := int(value[0])
				value = value[1:]
				if size == 0 || size > len(value) || !validProtocolText(string(value[:size])) || len(m.ALPN) >= 32 {
					return nil, protocolError()
				}
				m.ALPN = append(m.ALPN, string(value[:size]))
				value = value[size:]
			}
		case 43:
			if len(value) < 1 || int(value[0]) != len(value)-1 || (len(value)-1)%2 != 0 {
				return nil, protocolError()
			}
			for p := 1; p < len(value); p += 2 {
				m.AdvertisedVersions = append(m.AdvertisedVersions, binary.BigEndian.Uint16(value[p:p+2]))
			}
		}
	}
	return m, nil
}
