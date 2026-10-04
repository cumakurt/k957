package core

import (
	"bytes"
	"compress/gzip"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/netip"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"time"
)

type CloudReference struct {
	EventID     string `json:"event_id"`
	Version     string `json:"event_version"`
	Account     string `json:"recipient_account_id,omitempty"`
	Region      string `json:"region,omitempty"`
	EventSource string `json:"event_source"`
	EventName   string `json:"event_name"`
	Origin      string `json:"source_address,omitempty"`
	ErrorCode   string `json:"error_code,omitempty"`
}

func cloudTrailBody(ctx context.Context, raw []byte) ([]byte, error) {
	if len(raw) > 8<<20 {
		return nil, errors.New("CloudTrail input exceeds 8 MiB")
	}
	if len(raw) > 2 && raw[0] == 0x1f && raw[1] == 0x8b {
		reader, err := gzip.NewReader(bytes.NewReader(raw))
		if err != nil {
			return nil, err
		}
		defer reader.Close()
		body, err := io.ReadAll(io.LimitReader(&contextReader{ctx: ctx, r: reader}, (8<<20)+1))
		if err != nil {
			return nil, err
		}
		if len(body) > 8<<20 {
			return nil, errors.New("CloudTrail decompression exceeds 8 MiB")
		}
		return body, nil
	}
	return raw, nil
}

func parseCloudTrail(ctx context.Context, raw []byte, item Item, budget int) ([]Event, ParseSummary, bool) {
	summary := ParseSummary{Evidence: item.ID, Format: "CloudTrail", SkipReasons: map[string]int{}}
	body, err := cloudTrailBody(ctx, raw)
	if err != nil {
		summary.Error = err.Error()
		return nil, summary, true
	}
	var envelope map[string]json.RawMessage
	if json.Unmarshal(body, &envelope) != nil || envelope["Records"] == nil {
		return nil, summary, false
	}
	if err := validateExternalJSON(body); err != nil {
		summary.Error = err.Error()
		return nil, summary, true
	}
	var records []json.RawMessage
	if err := json.Unmarshal(envelope["Records"], &records); err != nil || records == nil || len(records) > 10000 {
		summary.Error = "CloudTrail Records must be an array of at most 10000 objects"
		return nil, summary, true
	}
	summary.Rows = len(records)
	events := []Event{}
	for ordinal, record := range records {
		if err := ctx.Err(); err != nil {
			summary.Error = err.Error()
			summary.Limited = true
			break
		}
		var fields map[string]json.RawMessage
		if json.Unmarshal(record, &fields) != nil || fields == nil {
			summary.Skipped++
			summary.SkipReasons["invalid_record"]++
			continue
		}
		str := func(name string) string {
			var value string
			if json.Unmarshal(fields[name], &value) != nil || len(value) > 4096 {
				return ""
			}
			return value
		}
		version, id, source, name, rawTime := str("eventVersion"), str("eventID"), str("eventSource"), str("eventName"), str("eventTime")
		stamp, timeErr := time.Parse(time.RFC3339Nano, rawTime)
		_, minorErr := strconv.ParseUint(strings.TrimPrefix(version, "1."), 10, 16)
		if minorErr != nil || !strings.HasPrefix(version, "1.") || len(version) > 16 || id == "" || len(id) > 256 || source == "" || len(source) > 256 || name == "" || len(name) > 256 || timeErr != nil || stamp.IsZero() {
			summary.Skipped++
			summary.SkipReasons["unsupported_version_or_fields"]++
			continue
		}
		if len(events) >= max(0, budget) {
			summary.Skipped++
			summary.Limited = true
			summary.SkipReasons["event_limit"]++
			continue
		}
		user := ""
		var identity map[string]json.RawMessage
		if json.Unmarshal(fields["userIdentity"], &identity) == nil {
			for _, key := range []string{"arn", "principalId"} {
				if json.Unmarshal(identity[key], &user) == nil && user != "" && len(user) <= 4096 {
					break
				}
				user = ""
			}
		}
		region, account, origin := str("awsRegion"), str("recipientAccountId"), str("sourceIPAddress")
		ip := ""
		if parsed, e := netip.ParseAddr(origin); e == nil {
			ip = parsed.String()
		}
		events = append(events, Event{Time: stamp.UTC(), OriginalTime: rawTime, Type: "cloud_api", User: user, Host: account + "/" + region, SourceIP: ip, Evidence: item.ID, Source: item.Source,
			Detail: source + ":" + name, Native: &NativeRecord{Parser: "cloudtrail", Record: fmt.Sprint(ordinal + 1), TimeField: "eventTime", TimeEncoding: "RFC3339"},
			Cloud: &CloudReference{EventID: id, Version: version, Account: account, Region: region, EventSource: source, EventName: name, Origin: origin, ErrorCode: str("errorCode")}})
	}
	summary.Parsed = len(events)
	return events, summary, true
}

type SourceImportFile struct {
	Name     string       `json:"name"`
	SHA256   string       `json:"sha256"`
	Bytes    int64        `json:"bytes"`
	Coverage ParseSummary `json:"coverage"`
}
type SourceImportReceipt struct {
	Schema             string             `json:"schema"`
	Provider           string             `json:"provider"`
	Files              []SourceImportFile `json:"files"`
	ExportCompleteness string             `json:"export_completeness"`
	Notes              []string           `json:"notes"`
}

// ImportCloudTrail copies bounded, caller-selected offline exports. It does not
// contact AWS, accept credentials or infer that a provider export is complete.
func ImportCloudTrail(ctx context.Context, source string, opts Options) (Manifest, error) {
	var empty Manifest
	info, err := os.Lstat(source)
	if err != nil {
		return empty, err
	}
	if !info.IsDir() || info.Mode()&os.ModeSymlink != 0 {
		return empty, errors.New("source import requires a real export directory")
	}
	dir, err := os.MkdirTemp("", "k957-cloudtrail-")
	if err != nil {
		return empty, err
	}
	defer os.RemoveAll(dir)
	rawDir := filepath.Join(dir, "exports")
	if err = os.Mkdir(rawDir, 0700); err != nil {
		return empty, err
	}
	receipt := SourceImportReceipt{Schema: "k957-source-import/1", Provider: "aws-cloudtrail-offline", Files: []SourceImportFile{}, ExportCompleteness: "unknown", Notes: []string{"Only supplied JSON/JSON.gz files are imported. No provider API, credentials, pagination, digest-chain authentication or delivery completeness is verified.", "Each file has an independent byte identity. Event IDs are upstream assertions; duplicates across exports are retained with distinct evidence/record references.", "Interpretation projects selected CloudTrail major-version-1 fields. Request/response bodies and other fields remain in raw exports and are not interpreted."}}
	var total int64
	err = filepath.WalkDir(source, func(path string, entry os.DirEntry, walkErr error) error {
		if walkErr != nil {
			return walkErr
		}
		if err := ctx.Err(); err != nil {
			return err
		}
		if path == source {
			return nil
		}
		rel, e := filepath.Rel(source, path)
		if e != nil {
			return e
		}
		name := filepath.ToSlash(rel)
		if !validReportName(name) || entry.Type()&os.ModeSymlink != 0 {
			return errors.New("invalid export path or symlink")
		}
		dest := filepath.Join(rawDir, rel)
		if entry.IsDir() {
			return os.Mkdir(dest, 0700)
		}
		if len(receipt.Files) >= 100 || (!strings.HasSuffix(strings.ToLower(name), ".json") && !strings.HasSuffix(strings.ToLower(name), ".json.gz")) {
			return errors.New("import supports at most 100 JSON/JSON.gz files")
		}
		sum, size, e := stageRawImage(ctx, path, dest, "", 8<<20)
		if e != nil {
			return e
		}
		total += size
		if total > 128<<20 {
			return errors.New("source import exceeds 128 MiB")
		}
		body, e := ReadLimited(dest, 8<<20)
		if e != nil {
			return e
		}
		_, summary, handled := parseCloudTrail(ctx, body, Item{Source: name}, 10000)
		if !handled || summary.Error != "" {
			return fmt.Errorf("unsupported CloudTrail export %q: %s", name, summary.Error)
		}
		receipt.Files = append(receipt.Files, SourceImportFile{Name: name, SHA256: sum, Bytes: size, Coverage: summary})
		return nil
	})
	if err != nil {
		return empty, err
	}
	if len(receipt.Files) == 0 {
		return empty, errors.New("export directory is empty")
	}
	if err = WriteJSONNew(filepath.Join(dir, "source-import.json"), receipt); err != nil {
		return empty, err
	}
	opts.Root = dir
	opts.MaxFile = 8 << 20
	opts.MaxTotal = 129 << 20
	opts.MaxFiles = 101
	opts.Acquisition = &AcquisitionGuarantees{Method: "authorized-offline-export", Origin: "provider_export_bytes", Notes: receipt.Notes}
	return Collect(ctx, opts)
}
