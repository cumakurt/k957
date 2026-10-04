package core

import "sort"

const CoverageSchema = "k957-coverage/1"

// Coverage counts one unit within a named stage. Eligible is the count seen
// so far when TotalKnown is false; Omitted is then a lower bound.
type Coverage struct {
	Schema     string         `json:"schema"`
	Stage      string         `json:"stage"`
	Format     string         `json:"format,omitempty"`
	Unit       string         `json:"unit"`
	Status     string         `json:"status"`
	Eligible   int64          `json:"eligible"`
	Emitted    int64          `json:"emitted"`
	Omitted    int64          `json:"omitted"`
	TotalKnown bool           `json:"total_known"`
	Limit      int64          `json:"limit,omitempty"`
	Reasons    map[string]int `json:"reasons,omitempty"`
}

func coverage(stage, unit string, eligible, emitted, limit int64, known bool) Coverage {
	c := Coverage{Schema: CoverageSchema, Stage: stage, Unit: unit, Eligible: eligible, Emitted: emitted, TotalKnown: known, Limit: limit, Status: "complete"}
	if eligible > emitted {
		c.Omitted = eligible - emitted
	}
	if !known || c.Omitted > 0 {
		c.Status = "partial"
	}
	return c
}

func analysisCoverage(a Analysis) []Coverage {
	out := []Coverage{coverage("inventory", "objects", int64(len(a.Manifest.Items)), int64(len(a.FileTypes)), 0, true)}
	if a.Canceled {
		out[0].Status = "canceled"
	}
	groups := map[string]*Coverage{}
	for _, s := range a.ParseSummaries {
		c := groups[s.Format]
		if c == nil {
			v := coverage("parser", "records", 0, 0, 0, true)
			v.Format = s.Format
			v.Reasons = map[string]int{}
			c = &v
			groups[s.Format] = c
		}
		c.Eligible += int64(s.Rows)
		c.Emitted += int64(s.Parsed)
		c.Omitted += int64(max(s.Skipped, s.Rows-s.Parsed))
		for reason, n := range s.SkipReasons {
			c.Reasons[reason] += n
		}
		if s.Limited {
			c.TotalKnown = false
			c.Reasons["resource_limit"]++
		}
		if s.Error != "" {
			c.TotalKnown = false
			c.Reasons["parser_error"]++
		}
		if s.Format == "unparsed" {
			c.Unit = "objects"
			c.Eligible++
			c.Omitted++
			c.Status = "unsupported"
		} else if s.Limited || s.Error != "" || s.Skipped > 0 || len(s.SkipReasons) > 0 {
			c.Status = "partial"
		}
	}
	keys := make([]string, 0, len(groups))
	for k := range groups {
		keys = append(keys, k)
	}
	sort.Strings(keys)
	for _, k := range keys {
		out = append(out, *groups[k])
	}
	f := coverage("findings", "findings", int64(len(a.Findings)), int64(len(a.Findings)), findingLimit, !a.FindingsTruncated)
	if a.FindingsTruncated {
		f.Reasons = map[string]int{"resource_limit": 1}
	}
	out = append(out, f)
	for _, r := range a.RuleEvaluations {
		c := coverage("structured_rules", "matches", int64(r.Matched), int64(r.Emitted), findingLimit, !a.Canceled)
		if r.Error != "" {
			c.Status = "failed"
			c.TotalKnown = false
			c.Reasons = map[string]int{"rule_error": 1}
		}
		out = append(out, c)
	}
	metadata := coverage("acquisition_metadata", "objects", 0, 0, 0, true)
	for _, item := range a.Manifest.Items {
		if item.Kind != "file" {
			continue
		}
		metadata.Eligible++
		if item.Metadata != nil && item.Metadata.Status == "captured" {
			metadata.Emitted++
		} else {
			metadata.Omitted++
		}
	}
	if metadata.Omitted > 0 {
		metadata.Status = "partial"
		metadata.Reasons = map[string]int{"metadata_omitted": int(metadata.Omitted)}
	}
	if metadata.Eligible > 0 {
		out = append(out, metadata)
	}
	for _, n := range a.NetworkInterpretations {
		c := coverage("network_protocols", "observations", int64(len(n.Observations)+n.Omissions["protocol_metadata_limit"]), int64(len(n.Observations)), 5000, !n.Limited && len(n.Omissions) == 0)
		c.Reasons = n.Omissions
		out = append(out, c)
	}
	var refs, emitted int64
	for _, c := range a.Correlations {
		refs += int64(c.Events)
		emitted += int64(len(c.References))
	}
	out = append(out, coverage("correlation_references", "references", refs, emitted, 200, true))
	for _, m := range a.Memories {
		kernel := coverage("memory_kernel", "plugins", 0, 0, 0, false)
		kernel.Status = "unsupported"
		kernel.Reasons = map[string]int{"not_run": 1}
		if m.Kernel != nil {
			good := int64(0)
			for _, run := range m.Kernel.Examinations {
				if run.Status == "interpreted" {
					good++
				}
			}
			kernel = coverage("memory_kernel", "plugins", int64(len(m.Kernel.Examinations)+len(m.Kernel.Unavailable)), good, 0, true)
			if good < int64(len(m.Kernel.Examinations)) {
				kernel.Reasons = map[string]int{"plugin_failure": int(int64(len(m.Kernel.Examinations)) - good)}
			}
			if len(m.Kernel.Unavailable) > 0 {
				if kernel.Reasons == nil {
					kernel.Reasons = map[string]int{}
				}
				kernel.Reasons["unavailable_plugin"] = len(m.Kernel.Unavailable)
			}
		}
		out = append(out, kernel)
		c := coverage("memory", "observations", int64(len(m.Observations)), int64(len(m.Observations)), 0, !m.ObservationsLimited)
		if m.Results != nil {
			c = coverage("memory", "observations", m.Results.Observations, m.Results.Observations, 0, true)
			out = append(out, coverage("memory_results", "records", m.Results.Rows, m.Results.Rows, 0, true))
			out = append(out, coverage("memory_preview", "observations", m.Results.Observations, int64(len(m.Observations)), memoryObsTotal, true))
			out = append(out, coverage("memory_preview", "matches", m.Results.Hits, int64(len(m.Hits)), memoryHitTotal, true), coverage("memory_preview", "urls", m.Results.URLs, int64(len(m.URLs)), memoryURLLimit, true))
		}
		out = append(out, c)
	}
	if a.Indicators != nil {
		out = append(out, coverage("offline_indicators", "matches", int64(len(a.Indicators.Matches)), int64(len(a.Indicators.Matches)), 0, true))
	}
	return out
}

// Shared coverage contains only known stage/format/unit/reason enums. Do not
// expose an arbitrary stage name or parser error supplied by evidence.
func sharedCoverage(rows []Coverage) []Coverage {
	out := make([]Coverage, 0, len(rows))
	for _, c := range rows {
		c.Stage = shareEnum(c.Stage, "inventory", "parser", "findings", "correlation_references", "memory", "collections", "duplicates", "hash_matches", "extension_mismatches", "case_events", "structured_rules", "acquisition_metadata", "network_protocols", "memory_results", "memory_preview", "memory_kernel", "offline_indicators")
		c.Unit = shareEnum(c.Unit, "objects", "records", "findings", "references", "observations", "collections", "groups", "matches", "events", "plugins", "urls")
		c.Status = shareEnum(c.Status, "complete", "partial", "unsupported", "canceled", "failed")
		if c.Format != "" {
			c.Format = shareEnum(c.Format, "text/RFC3339", "CSV", "JSONL", "WindowsEventXML", "WindowsPrefetch", "WindowsScheduledTask", "launchd", "systemd", "PCAP", "PCAPNG", "memory", "unparsed", "SQLite", "EVTX", "CloudTrail", "BinaryPlist", "Registry", "USN")
		}
		reasons := map[string]int{}
		for reason, n := range c.Reasons {
			key := shareEnum(reason, "resource_limit", "parser_error", "text_size_or_budget", "unsupported_text_encoding_or_binary", "verification_failed", "not_run", "plugin_failure", "unavailable_plugin")
			reasons[key] += n
		}
		c.Reasons = reasons
		out = append(out, c)
	}
	return out
}
