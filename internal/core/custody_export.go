package core

import (
	"bytes"
	"encoding/csv"
	"strconv"
	"time"
)

func exportCustodyCSV(s *CustodyStatus, path string) error {
	var b bytes.Buffer
	w := csv.NewWriter(&b)
	w.Write([]string{"sequence", "action", "actor", "from", "to", "location", "note", "occurred_at", "recorded_at", "signer_sha256", "previous"})
	for _, e := range s.Events {
		w.Write([]string{strconv.Itoa(e.Sequence), e.Action, csvSafe(e.Actor), csvSafe(e.From), csvSafe(e.To), csvSafe(e.Location), csvSafe(e.Note), e.OccurredAt.Format(time.RFC3339Nano), e.RecordedAt.Format(time.RFC3339Nano), e.Signer, e.Previous})
	}
	w.Flush()
	if e := w.Error(); e != nil {
		return e
	}
	return WriteNew(path, b.Bytes())
}
