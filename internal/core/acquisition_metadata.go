package core

import (
	"os"
	"time"
)

type AcquisitionGuarantees struct {
	Method                      string   `json:"method"`
	Origin                      string   `json:"origin"`
	FilesystemSnapshot          bool     `json:"filesystem_snapshot"`
	MultiFileAtomic             bool     `json:"multi_file_atomic"`
	SQLiteTransactionConsistent bool     `json:"sqlite_transaction_consistent"`
	Notes                       []string `json:"notes"`
}

type FileMetadata struct {
	Sampled    time.Time           `json:"sampled"`
	Epoch      string              `json:"epoch,omitempty"`
	Status     string              `json:"status"`
	Device     string              `json:"device,omitempty"`
	Inode      string              `json:"inode,omitempty"`
	UID        *uint32             `json:"uid,omitempty"`
	GID        *uint32             `json:"gid,omitempty"`
	Links      uint64              `json:"links,omitempty"`
	Accessed   *time.Time          `json:"accessed,omitempty"`
	Changed    *time.Time          `json:"changed,omitempty"`
	Created    *time.Time          `json:"created,omitempty"`
	Attributes []ExtendedAttribute `json:"attributes,omitempty"`
	Omissions  []string            `json:"omissions,omitempty"`
}

type ExtendedAttribute struct {
	Name       string `json:"name"`
	NameBase64 string `json:"name_base64,omitempty"`
	Value      string `json:"value_base64"`
}

func sampledFileMetadata(file *os.File, info os.FileInfo, epoch string) *FileMetadata {
	metadata := captureFileMetadata(file, info)
	metadata.Sampled = time.Now().UTC()
	metadata.Epoch = epoch
	return metadata
}

const metadataAttributeBudget = 8 << 20

func boundMetadataAttributes(metadata *FileMetadata, used *int64) {
	if metadata == nil || len(metadata.Attributes) == 0 {
		return
	}
	encoded := int64(len(JSON(metadata.Attributes)))
	if encoded > metadataAttributeBudget-*used {
		metadata.Attributes = nil
		metadata.Status = "partial"
		metadata.Omissions = append(metadata.Omissions, "extended_attribute_aggregate_limit")
		return
	}
	*used += encoded
}

func liveFileGuarantees() *AcquisitionGuarantees {
	return &AcquisitionGuarantees{Method: "logical-live-files", Origin: "raw_file_bytes", Notes: []string{"Files are read individually. Metadata change detection is not an atomic filesystem or multi-file snapshot.", "Filesystem device identifiers do not prove physical-device separation.", "SQLite main/sidecar copies may describe different transaction states. Use explicit sqlite-acquire for a separately identified logical backup."}}
}
