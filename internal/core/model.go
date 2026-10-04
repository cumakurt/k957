package core

import (
	"crypto/rand"
	"encoding/hex"
	"encoding/json"
	"errors"
	"io"
	"os"
	"time"
)

const Version = "0.15.0"
const Schema = "k957-evidence/1"
const ResumeSchema = "k957-evidence/2"

type Item struct {
	Metadata  *FileMetadata `json:"metadata,omitempty"`
	Parts     []Part        `json:"parts,omitempty"`
	ID        string        `json:"id"`
	Source    string        `json:"source"`
	Object    string        `json:"object"`
	Kind      string        `json:"kind"`
	Size      int64         `json:"size"`
	SHA256    string        `json:"sha256"`
	Modified  time.Time     `json:"modified"`
	Collected time.Time     `json:"collected"`
	Mode      string        `json:"mode"`
	Changed   bool          `json:"changed_during_acquisition"`
}
type Issue struct {
	Source string `json:"source"`
	Reason string `json:"reason"`
}
type Manifest struct {
	Acquisition     *AcquisitionGuarantees `json:"acquisition,omitempty"`
	Epochs          []Epoch                `json:"epochs,omitempty"`
	InventoryFrozen bool                   `json:"inventory_frozen,omitempty"`
	Schema          string                 `json:"schema"`
	Version         string                 `json:"version"`
	ID              string                 `json:"id"`
	Case            string                 `json:"case"`
	Operator        string                 `json:"operator"`
	Scope           string                 `json:"scope"`
	Host            string                 `json:"host"`
	OS              string                 `json:"os"`
	Arch            string                 `json:"arch"`
	Started         time.Time              `json:"started"`
	Finished        time.Time              `json:"finished"`
	Status          string                 `json:"status"`
	Items           []Item                 `json:"items"`
	Issues          []Issue                `json:"issues"`
}
type Options struct {
	Acquisition                               *AcquisitionGuarantees
	EncryptionKey                             string
	Root, Out, Case, Operator, Scope, SignKey string
	// Paths are additional directories or regular files collected after Root.
	// Single-pass collection only.
	Paths             []string
	System            bool
	MaxFile, MaxTotal int64
	MaxFiles          int
	// OnSkip, when set, receives symlinks and special files found below Paths
	// instead of recording them as manifest issues.
	OnSkip func(path, reason string)
}

func ID() string {
	b := make([]byte, 16)
	if _, e := io.ReadFull(rand.Reader, b); e != nil {
		panic(e)
	}
	return hex.EncodeToString(b)
}
func WriteNew(path string, b []byte) error {
	f, e := os.OpenFile(path, os.O_CREATE|os.O_EXCL|os.O_WRONLY, 0600)
	if e != nil {
		return e
	}
	_, e = f.Write(b)
	if e == nil {
		e = f.Sync()
	}
	c := f.Close()
	if e != nil {
		return e
	}
	return c
}
func ReadLimited(path string, n int64) ([]byte, error) {
	f, e := os.Open(path)
	if e != nil {
		return nil, e
	}
	defer f.Close()
	b, e := io.ReadAll(io.LimitReader(f, n+1))
	if int64(len(b)) > n {
		return nil, errors.New("input limit exceeded")
	}
	return b, e
}
func JSON(v any) []byte { b, _ := json.MarshalIndent(v, "", "  "); return append(b, '\n') }

func MarshalJSON(v any) ([]byte, error) {
	body, err := json.MarshalIndent(v, "", "  ")
	if err != nil {
		return nil, err
	}
	return append(body, '\n'), nil
}

func WriteJSONNew(path string, v any) error {
	body, err := MarshalJSON(v)
	if err != nil {
		return err
	}
	return WriteNew(path, body)
}

// Part identifies an acquired byte range and the invocation that read it.
type Part struct {
	Offset   int64     `json:"offset"`
	Size     int64     `json:"size"`
	SHA256   string    `json:"sha256"`
	Epoch    string    `json:"epoch"`
	Acquired time.Time `json:"acquired"`
}
type Epoch struct {
	Host     string    `json:"host"`
	OS       string    `json:"os"`
	Arch     string    `json:"arch"`
	ID       string    `json:"id"`
	Started  time.Time `json:"started"`
	Finished time.Time `json:"finished"`
	Outcome  string    `json:"outcome"`
}
