package main

import (
	"context"
	"encoding/json"
	"flag"
	"k957/internal/core"
	"net/url"
	"os"
	"os/signal"
	"strconv"
)

func runCaseSelection(args []string) error {
	f := flag.NewFlagSet("case-bookmark", flag.ContinueOnError)
	dir := f.String("case", "", "derived case directory")
	out := f.String("out", "", "new signed bookmark/subset directory")
	title := f.String("title", "", "investigation bookmark title")
	analyst := f.String("analyst", "", "examiner identifier")
	note := f.String("note", "", "required selection reason")
	key := f.String("sign-key", "", "Ed25519 bookmark signer")
	text := f.String("text", "", "literal search filter")
	kind := f.String("kind", "", "indexed record kind")
	host := f.String("host", "", "collection host")
	digest := f.String("digest", "", "collection SHA-256 scope")
	evidence := f.String("evidence", "", "evidence ID scope")
	nativeParser := f.String("native-parser", "", "exact native parser name; event rows only")
	nativeRecord := f.String("native-record", "", "exact native record ID; event rows only")
	usnFileID := f.String("usn-file-id", "", "exact USN file ID in raw little-endian hex; event rows only")
	after := f.String("after", "", "inclusive RFC3339 time")
	before := f.String("before", "", "inclusive RFC3339 time")
	limit := f.Int("limit", 100, "selected page size, 1..200")
	offset := f.Int("offset", 0, "selected page offset")
	if stop, err := parseFlags(f, args); stop || err != nil {
		return err
	}
	q, err := parseCaseQuery(url.Values{"native-parser": {*nativeParser}, "native-record": {*nativeRecord}, "usn-file-id": {*usnFileID}, "text": {*text}, "kind": {*kind}, "host": {*host}, "digest": {*digest}, "evidence": {*evidence}, "after": {*after}, "before": {*before}, "limit": {strconv.Itoa(*limit)}, "offset": {strconv.Itoa(*offset)}})
	if err != nil {
		return err
	}
	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt)
	defer stop()
	result, err := core.ExportCaseSelection(ctx, *dir, *out, *title, *analyst, *note, *key, q)
	if err != nil {
		return err
	}
	return json.NewEncoder(os.Stdout).Encode(result)
}
