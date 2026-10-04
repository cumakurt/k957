package core

import (
	"bytes"
	"compress/gzip"
	"context"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

const cloudFixture = `{"Records":[{"eventVersion":"1.11","eventID":"fixture-id","eventTime":"2024-01-01T00:00:00Z","eventSource":"ec2.amazonaws.com","eventName":"StopInstances","awsRegion":"eu-west-1","recipientAccountId":"111122223333","sourceIPAddress":"192.0.2.1","userIdentity":{"arn":"arn:aws:iam::111122223333:user/Test"},"requestParameters":{"ignored":"raw only"}}]}`

func TestCloudTrailRawImportAndReferences(t *testing.T) {
	dir := t.TempDir()
	source := filepath.Join(dir, "export")
	if err := os.Mkdir(source, 0700); err != nil {
		t.Fatal(err)
	}
	var zipped bytes.Buffer
	z := gzip.NewWriter(&zipped)
	z.Write([]byte(cloudFixture))
	z.Close()
	if err := os.WriteFile(filepath.Join(source, "records.json.gz"), zipped.Bytes(), 0600); err != nil {
		t.Fatal(err)
	}
	out := filepath.Join(dir, "source.k957")
	m, err := ImportCloudTrail(context.Background(), source, Options{Out: out, Case: "SOURCE", Operator: "Test", Scope: "selected offline export"})
	if err != nil {
		t.Fatal(err)
	}
	if m.Acquisition.Method != "authorized-offline-export" || len(m.Items) != 2 {
		t.Fatal(m)
	}
	p, err := Open(out, "")
	if err != nil {
		t.Fatal(err)
	}
	defer p.Zip.Close()
	a := Analyze(p, nil)
	var cloud []Event
	for _, ev := range a.Timeline {
		if ev.Cloud != nil {
			cloud = append(cloud, ev)
		}
	}
	if len(cloud) != 1 || cloud[0].Cloud.EventID != "fixture-id" || cloud[0].Native.Record != "1" || cloud[0].SourceIP != "192.0.2.1" {
		t.Fatal(cloud)
	}
	for _, item := range p.Manifest.Items {
		if strings.HasSuffix(item.Source, ".gz") {
			raw, e := readEntry(p.Files[item.Object], 8<<20)
			if e != nil || !bytes.Equal(raw, zipped.Bytes()) {
				t.Fatal("raw export changed", e)
			}
		}
	}
}

func TestCloudTrailCorruptionLimitsAndDuplicates(t *testing.T) {
	item := Item{ID: "E1", Source: "cloud.json"}
	_, s, ok := parseCloudTrail(context.Background(), []byte(strings.Replace(cloudFixture, `"eventID":"fixture-id"`, `"eventID":"one","eventID":"two"`, 1)), item, 10)
	if !ok || s.Error == "" {
		t.Fatal("duplicate provider keys accepted")
	}
	events, s, ok := parseCloudTrail(context.Background(), []byte(cloudFixture), item, 0)
	if !ok || len(events) != 0 || !s.Limited || s.Skipped != 1 {
		t.Fatal("event limit hidden", s)
	}
	_, s, ok = parseCloudTrail(context.Background(), []byte(strings.Replace(cloudFixture, `"1.11"`, `"2.0"`, 1)), item, 10)
	if !ok || s.Skipped != 1 || s.SkipReasons["unsupported_version_or_fields"] != 1 {
		t.Fatal("future version accepted", s)
	}
	var compressed bytes.Buffer
	z := gzip.NewWriter(&compressed)
	z.Write(bytes.Repeat([]byte("x"), (8<<20)+1))
	z.Close()
	if _, err := cloudTrailBody(context.Background(), compressed.Bytes()); err == nil {
		t.Fatal("decompression bomb accepted")
	}
}
