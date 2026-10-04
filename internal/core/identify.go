package core

import (
	"archive/zip"
	"bytes"
	"encoding/binary"
	"encoding/csv"
	"io"
	"path/filepath"
	"strconv"
	"strings"
)

const identityPrefix = 560

// FileIdentity is a magic-byte classification of one evidence object.
// It is a hint for triage, not a parser of the format.
type FileIdentity struct {
	Host              string `json:"host,omitempty"`
	Evidence          string `json:"evidence"`
	Source            string `json:"source"`
	MediaType         string `json:"media_type"`
	Description       string `json:"description"`
	MatchedBy         string `json:"matched_by"`
	ExtensionMismatch bool   `json:"extension_mismatch,omitempty"`
}

func identifyItem(f *zip.File, it Item) FileIdentity {
	id := FileIdentity{Evidence: it.ID, Source: it.Source, MediaType: "application/octet-stream", Description: "no recognized signature", MatchedBy: "none"}
	if f == nil {
		id.Description = "missing object"
		id.MatchedBy = "error"
		return id
	}
	b, e := readObjectPrefix(f, identityPrefix)
	if e != nil {
		id.Description = "header unreadable"
		id.MatchedBy = "error"
		return id
	}
	return identifyItemPrefix(it, b)
}

func identifyVerifiedItem(p *Package, it Item) FileIdentity {
	if prefix, ok := p.VerifiedPrefixes[it.Object]; ok {
		return identifyItemPrefix(it, prefix)
	}
	return identifyItem(p.Files[it.Object], it)
}

func identifyItemPrefix(it Item, b []byte) FileIdentity {
	id := FileIdentity{Evidence: it.ID, Source: it.Source, MediaType: "application/octet-stream", Description: "no recognized signature", MatchedBy: "none"}
	media, desc := identifyHeader(b)
	if media == "" && usnCandidate(it.Source) {
		id.MediaType, id.Description, id.MatchedBy = "application/x-windows-usn-journal", "USN journal candidate; filename hint requires record validation", "filename"
		return id
	}
	if media != "" {
		id.MediaType = media
		id.Description = desc
		id.MatchedBy = "magic"
		id.ExtensionMismatch = extensionMismatch(it.Source, media)
	}
	return id
}

func readObjectPrefix(f *zip.File, n int) ([]byte, error) {
	r, e := f.Open()
	if e != nil {
		return nil, e
	}
	defer r.Close()
	buf := make([]byte, n)
	k, e := io.ReadFull(r, buf)
	if e == io.EOF || e == io.ErrUnexpectedEOF {
		return buf[:k], nil
	}
	if e != nil {
		return nil, e
	}
	return buf[:k], nil
}

func identifyHeader(b []byte) (media, description string) {
	switch {
	case bytes.HasPrefix(b, []byte("bplist00")):
		return "application/x-apple-binary-plist", "Apple binary property list"
	case bytes.HasPrefix(b, []byte("SQLite format 3\x00")):
		return "application/vnd.sqlite3", "SQLite 3 database"
	case bytes.HasPrefix(b, []byte("ElfFile\x00")):
		return "application/x-ms-evtx", "Windows Event Log (EVTX)"
	case bytes.HasPrefix(b, []byte("regf")):
		return "application/x-windows-registry", "Windows registry hive"
	case bytes.HasPrefix(b, []byte("%PDF-")):
		return "application/pdf", "PDF document"
	case bytes.HasPrefix(b, []byte{0x89, 'P', 'N', 'G', '\r', '\n', 0x1a, '\n'}):
		return "image/png", "PNG image"
	case bytes.HasPrefix(b, []byte{0xff, 0xd8, 0xff}):
		return "image/jpeg", "JPEG image"
	case bytes.HasPrefix(b, []byte("GIF87a")), bytes.HasPrefix(b, []byte("GIF89a")):
		return "image/gif", "GIF image"
	case bytes.HasPrefix(b, []byte{0x50, 0x4b, 0x03, 0x04}), bytes.HasPrefix(b, []byte{0x50, 0x4b, 0x05, 0x06}), bytes.HasPrefix(b, []byte{0x50, 0x4b, 0x07, 0x08}):
		return "application/zip", "ZIP container"
	case bytes.HasPrefix(b, []byte{0x1f, 0x8b}):
		return "application/gzip", "gzip stream"
	case bytes.HasPrefix(b, []byte{0x37, 0x7a, 0xbc, 0xaf, 0x27, 0x1c}):
		return "application/x-7z-compressed", "7-Zip archive"
	case bytes.HasPrefix(b, []byte("Rar!\x1a\x07")):
		return "application/vnd.rar", "RAR archive"
	case bytes.HasPrefix(b, []byte{0xd0, 0xcf, 0x11, 0xe0, 0xa1, 0xb1, 0x1a, 0xe1}):
		return "application/x-ole-storage", "OLE compound document"
	case bytes.HasPrefix(b, []byte{0x0a, 0x0d, 0x0d, 0x0a}):
		return "application/x-pcapng", "PCAPNG capture"
	case bytes.HasPrefix(b, []byte{0xd4, 0xc3, 0xb2, 0xa1}), bytes.HasPrefix(b, []byte{0xa1, 0xb2, 0xc3, 0xd4}), bytes.HasPrefix(b, []byte{0x4d, 0x3c, 0xb2, 0xa1}), bytes.HasPrefix(b, []byte{0xa1, 0xb2, 0x3c, 0x4d}):
		return "application/vnd.tcpdump.pcap", "classic PCAP capture"
	case len(b) >= 4 && binary.LittleEndian.Uint32(b[:4]) == limeMagic:
		return "application/x-lime", "LiME memory image"
	case bytes.HasPrefix(b, []byte{0x7f, 'E', 'L', 'F'}):
		return "application/x-elf", "ELF executable"
	case macho(b):
		return "application/x-mach-binary", "Mach-O executable"
	case bytes.HasPrefix(b, []byte{0x00, 'a', 's', 'm'}):
		return "application/wasm", "WebAssembly module"
	case peHeader(b):
		return "application/vnd.microsoft.portable-executable", "Windows PE executable"
	case bytes.HasPrefix(b, []byte("MZ")):
		return "application/x-dos-mz", "DOS MZ header; PE signature not within the inspected prefix"
	case bytes.HasPrefix(b, []byte("#!")):
		return "text/x-script", "script with a shebang"
	case bytes.HasPrefix(b, []byte("<?xml")), bytes.HasPrefix(bytes.TrimPrefix(b, []byte{0xef, 0xbb, 0xbf}), []byte("<?xml")):
		return "text/xml", "XML text"
	case bytes.HasPrefix(b, []byte{0xef, 0xbb, 0xbf}):
		return "text/plain", "UTF-8 text with a byte order mark"
	default:
		return "", ""
	}
}

func peHeader(b []byte) bool {
	if len(b) < 0x40 || !bytes.HasPrefix(b, []byte("MZ")) {
		return false
	}
	off := binary.LittleEndian.Uint32(b[0x3c:])
	if off > 4096 || int(off)+4 > len(b) {
		return false
	}
	return bytes.Equal(b[off:off+4], []byte("PE\x00\x00"))
}

func macho(b []byte) bool {
	magics := [][]byte{{0xfe, 0xed, 0xfa, 0xce}, {0xfe, 0xed, 0xfa, 0xcf}, {0xce, 0xfa, 0xed, 0xfe}, {0xcf, 0xfa, 0xed, 0xfe}}
	for _, m := range magics {
		if bytes.HasPrefix(b, m) {
			return true
		}
	}
	return false
}

var extMedia = map[string]string{
	".exe":    "application/vnd.microsoft.portable-executable",
	".dll":    "application/vnd.microsoft.portable-executable",
	".png":    "image/png",
	".jpg":    "image/jpeg",
	".jpeg":   "image/jpeg",
	".gif":    "image/gif",
	".pdf":    "application/pdf",
	".zip":    "application/zip",
	".docx":   "application/zip",
	".xlsx":   "application/zip",
	".pptx":   "application/zip",
	".jar":    "application/zip",
	".apk":    "application/zip",
	".k957":   "application/zip",
	".gz":     "application/gzip",
	".sqlite": "application/vnd.sqlite3",
	".db":     "application/vnd.sqlite3",
	".evtx":   "application/x-ms-evtx",
	".pcap":   "application/vnd.tcpdump.pcap",
	".pcapng": "application/x-pcapng",
	".elf":    "application/x-elf",
	".so":     "application/x-elf",
	".wasm":   "application/wasm",
	".xml":    "text/xml",
	".sh":     "text/x-script",
}

var textExt = map[string]bool{
	".txt": true, ".log": true, ".json": true, ".csv": true, ".html": true, ".htm": true,
	".md": true, ".yml": true, ".yaml": true, ".conf": true, ".ini": true,
}

func extensionMismatch(source, media string) bool {
	ext := strings.ToLower(filepath.Ext(source))
	if ext == "" || media == "" || media == "application/octet-stream" {
		return false
	}
	if expected, ok := extMedia[ext]; ok {
		return expected != media
	}
	if textExt[ext] && media != "text/plain" && media != "text/xml" && media != "text/x-script" {
		return true
	}
	return false
}

func writeIdentities(a Analysis, path string) error {
	var b bytes.Buffer
	w := csv.NewWriter(&b)
	_ = w.Write([]string{"evidence_id", "source", "media_type", "description", "matched_by", "extension_mismatch"})
	for _, id := range a.FileTypes {
		_ = w.Write([]string{id.Evidence, csvSafe(id.Source), id.MediaType, csvSafe(id.Description), id.MatchedBy, strconv.FormatBool(id.ExtensionMismatch)})
	}
	w.Flush()
	if e := w.Error(); e != nil {
		return e
	}
	return WriteNew(path, b.Bytes())
}
