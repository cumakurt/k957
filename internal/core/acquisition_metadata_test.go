package core

import (
	"strings"
	"testing"
	"time"
)

func TestMetadataAggregateLimitIsExplicit(t *testing.T) {
	used := int64(metadataAttributeBudget - 100)
	m := &FileMetadata{Status: "captured", Attributes: []ExtendedAttribute{{Name: "user.fixture", Value: strings.Repeat("A", 1024)}}}
	boundMetadataAttributes(m, &used)
	if len(m.Attributes) != 0 || m.Status != "partial" || m.Omissions[0] != "extended_attribute_aggregate_limit" || used != metadataAttributeBudget-100 {
		t.Fatal("metadata budget hidden", m, used)
	}
}

func TestJSONEncodingFailureIsReported(t *testing.T) {
	value := Event{Time: time.Date(12000, 1, 1, 0, 0, 0, 0, time.UTC)}
	if _, err := MarshalJSON(value); err == nil {
		t.Fatal("invalid JSON time accepted")
	}
	if err := WriteJSONNew(t.TempDir()+"/event.json", value); err == nil {
		t.Fatal("failed JSON serialization published")
	}
}
