package core

import (
	"path/filepath"
	"strconv"
	"time"
)

func windowsEvents(events []Event) []Event {
	var result []Event
	for _, event := range events {
		if event.Windows != nil {
			result = append(result, event)
		}
	}
	return result
}

func exportWindowsEvents(a Analysis, out string) error {
	rows := [][]string{}
	for _, event := range a.Timeline {
		w := event.Windows
		if w == nil {
			continue
		}
		qualifiers, level, version := "", "", ""
		if w.Qualifiers != nil {
			qualifiers = strconv.Itoa(int(*w.Qualifiers))
		}
		if w.Level != nil {
			level = strconv.Itoa(int(*w.Level))
		}
		if w.Version != nil {
			version = strconv.Itoa(int(*w.Version))
		}
		rows = append(rows, []string{event.Evidence, event.Source, strconv.Itoa(event.Line), strconv.FormatInt(event.ByteOffset, 10), event.Time.Format(time.RFC3339Nano), event.OriginalTime, w.Provider, w.ProviderGUID, w.EventSource, strconv.Itoa(int(w.EventID)), qualifiers, w.RecordID, w.Channel, level, version, event.Host, event.User, event.Detail, string(JSON(w.Data)), strconv.FormatBool(w.PayloadOmitted), strconv.FormatBool(w.MessageTruncated)})
	}
	if len(rows) == 0 {
		return nil
	}
	return sharedCSV(filepath.Join(out, "windows-events.csv"), []string{"evidence", "source", "line", "byte_offset", "time_utc", "original_time", "provider", "provider_guid", "event_source", "event_id", "qualifiers", "record_id", "channel", "level", "version", "computer_normalized", "security_user_id", "message", "event_data_json", "payload_omitted", "message_truncated"}, rows)
}
