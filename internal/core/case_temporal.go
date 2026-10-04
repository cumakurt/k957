package core

import (
	"context"
	"errors"
	"path/filepath"
	"sort"
	"strconv"
	"strings"
	"time"
)

type ClockEstimate struct {
	SourceHost    string `json:"source_host,omitempty"`
	Digest        string `json:"collection_digest"`
	OffsetNS      int64  `json:"offset_ns"`
	UncertaintyNS int64  `json:"uncertainty_ns"`
	Reference     string `json:"reference"`
}
type IdentityMapping struct {
	Digest   string `json:"collection_digest"`
	Field    string `json:"field"`
	Original string `json:"original"`
	Identity string `json:"identity"`
	Reason   string `json:"reason"`
}
type TemporalPolicy struct {
	Schema     string            `json:"schema"`
	Clocks     []ClockEstimate   `json:"clocks"`
	Identities []IdentityMapping `json:"identities"`
}
type TemporalReference struct {
	RowID         int64           `json:"row_id"`
	Digest        string          `json:"collection_digest"`
	Reference     *EventReference `json:"reference"`
	EstimatedUTC  time.Time       `json:"estimated_utc"`
	UncertaintyNS int64           `json:"uncertainty_ns"`
	ClockKnown    bool            `json:"clock_estimate_supplied"`
}
type TemporalGroup struct {
	Field             string              `json:"field"`
	Value             string              `json:"value"`
	Scope             string              `json:"scope"`
	References        []TemporalReference `json:"references"`
	ReferencesOmitted int                 `json:"references_omitted"`
	ClockKnown        bool                `json:"clock_estimates_supplied_for_all"`
}
type TemporalResult struct {
	Schema       string          `json:"schema"`
	IndexSHA256  string          `json:"index_sha256"`
	PolicySHA256 string          `json:"policy_sha256"`
	Policy       TemporalPolicy  `json:"policy"`
	WindowNS     int64           `json:"window_ns"`
	Groups       []TemporalGroup `json:"groups"`
	Coverage     []Coverage      `json:"coverage"`
	Notes        []string        `json:"notes"`
}

func LoadTemporalPolicy(path string) (p TemporalPolicy, err error) {
	p = TemporalPolicy{Schema: "k957-temporal-policy/1", Clocks: []ClockEstimate{}, Identities: []IdentityMapping{}}
	if path == "" {
		return p, nil
	}
	if err = strictJSON(path, 1<<20, &p); err != nil {
		return p, err
	}
	return p, validateTemporalPolicy(p)
}

func validateTemporalPolicy(p TemporalPolicy) error {
	if p.Schema != "k957-temporal-policy/1" || len(p.Clocks) > 1000 || len(p.Identities) > 1000 {
		return errors.New("invalid temporal policy schema or bounds")
	}
	seen := map[string]bool{}
	for _, c := range p.Clocks {
		key := c.Digest + "/" + c.SourceHost
		if !validHash(c.Digest) || seen[key] || len(c.SourceHost) > 256 || c.OffsetNS < -int64(7*24*time.Hour) || c.OffsetNS > int64(7*24*time.Hour) || c.UncertaintyNS < 0 || c.UncertaintyNS > int64(24*time.Hour) || strings.TrimSpace(c.Reference) == "" || len(c.Reference) > 4096 {
			return errors.New("invalid clock estimate or missing reference")
		}
		seen[key] = true
	}
	seen = map[string]bool{}
	for _, m := range p.Identities {
		key := m.Digest + "\x00" + m.Field + "\x00" + m.Original
		if !validHash(m.Digest) || seen[key] || m.Field != "user" || m.Original == "" || len(m.Original) > 256 || m.Identity == "" || len(m.Identity) > 256 || m.Reason == "" || len(m.Reason) > 4096 {
			return errors.New("invalid explicit identity mapping")
		}
		seen[key] = true
	}
	return nil
}

func CorrelateCase(ctx context.Context, dir, field string, window time.Duration, policy TemporalPolicy) (result TemporalResult, err error) {
	if err = validateTemporalPolicy(policy); err != nil {
		return result, err
	}
	if field != "user" && field != "host" && field != "source_ip" && field != "destination_ip" {
		return result, errors.New("unsupported temporal field")
	}
	if window <= 0 || window > 24*time.Hour {
		return result, errors.New("temporal window must be positive and at most 24h")
	}
	path := filepath.Join(dir, "case-index.sqlite")
	before, e := fileSHA256Progress(path, "", 0, &verifyMeter{ctx: ctx})
	if e != nil {
		return result, e
	}
	result = TemporalResult{Schema: "k957-temporal-correlation/1", IndexSHA256: before, PolicySHA256: digestJSON(policy), Policy: policy, WindowNS: int64(window), Groups: []TemporalGroup{}, Notes: []string{"Groups are candidate temporal relationships, not causality or attribution. Unknown clock errors are unbounded; a configured window then applies only to displayed source times.", "User names are scoped to a collection and source host by default. Cross-collection user matches require explicit examiner identity mappings.", "Clock corrections are derived estimates supplied by the examiner; source timestamps are preserved. A positive offset means the source clock was ahead of UTC. Supplied estimates and mapping reasons are assertions, not independent verification."}}
	clocks := map[string]ClockEstimate{}
	identities := map[string]string{}
	for _, c := range policy.Clocks {
		clocks[c.Digest+"/"+c.SourceHost] = c
	}
	for _, m := range policy.Identities {
		identities[m.Digest+"\x00"+m.Field+"\x00"+m.Original] = m.Identity
	}
	buckets := map[string][]TemporalReference{}
	scopes := map[string]string{}
	values := map[string]string{}
	read := 0
	limited := false
	db, e := openCaseIndex(ctx, path)
	if e != nil {
		return result, e
	}
	defer db.Close()
	rows, e := db.QueryContext(ctx, "SELECT id,digest,host,payload FROM entries WHERE kind='event' ORDER BY seconds,nanos,id LIMIT 100001")
	if e != nil {
		return result, e
	}
	defer rows.Close()
	for rows.Next() {
		if read >= 100000 {
			limited = true
			break
		}
		read++
		var id int64
		var digest, host, payload string
		if e = rows.Scan(&id, &digest, &host, &payload); e != nil {
			return result, e
		}
		var ev Event
		if len(payload) > 256<<10 {
			return result, errors.New("temporal event exceeds bounds")
		}
		if e = custodyJSON([]byte(payload), &ev); e != nil {
			return result, e
		}
		if ev.Type == "collected" || ev.Type == "file_modified" {
			continue
		}
		value, ok := eventField(ev, field)
		if !ok {
			continue
		}
		scope := "value-only"
		if field == "user" {
			namespace := ev.Host
			if namespace == "" {
				namespace = host
			}
			scope = "collection:" + digest + "/host:" + namespace
			if mapped, ok := identities[digest+"\x00user\x00"+value]; ok {
				scope = "examiner-identity"
				value = mapped
			}
		}
		key := scope + "\x00" + value
		if len(buckets) >= 20000 && buckets[key] == nil {
			limited = true
			continue
		}
		sourceHost := ev.Host
		if sourceHost == "" {
			sourceHost = host
		}
		clock, known := clocks[digest+"/"+sourceHost]
		if !known && sourceHost == host {
			clock, known = clocks[digest+"/"]
		}
		stamp := ev.Time.Add(-time.Duration(clock.OffsetNS))
		buckets[key] = append(buckets[key], TemporalReference{RowID: id, Digest: digest, Reference: referenceEvent(ev), EstimatedUTC: stamp, UncertaintyNS: clock.UncertaintyNS, ClockKnown: known})
		scopes[key] = scope
		values[key] = value
	}
	if e = rows.Err(); e != nil {
		return result, e
	}
	rows.Close()
	db.Close()
	eligible := int64(0)
	keys := make([]string, 0, len(buckets))
	for key := range buckets {
		keys = append(keys, key)
	}
	sort.Strings(keys)
	for _, key := range keys {
		refs := buckets[key]
		sort.SliceStable(refs, func(i, j int) bool { return refs[i].EstimatedUTC.Before(refs[j].EstimatedUTC) })
		for start := 0; start < len(refs); {
			end := start + 1
			for end < len(refs) {
				distance := refs[end].EstimatedUTC.Sub(refs[start].EstimatedUTC)
				uncertainty := time.Duration(refs[end].UncertaintyNS + refs[start].UncertaintyNS)
				if distance > window+uncertainty {
					break
				}
				end++
			}
			if end-start >= 2 {
				unique := map[string]bool{}
				known := true
				for _, r := range refs[start:end] {
					unique[r.Digest+"/"+r.Reference.Evidence] = true
					known = known && r.ClockKnown
				}
				if len(unique) >= 2 {
					eligible++
					if len(result.Groups) < 2000 {
						count := min(end-start, 200)
						result.Groups = append(result.Groups, TemporalGroup{Field: field, Value: values[key], Scope: scopes[key], References: append([]TemporalReference(nil), refs[start:start+count]...), ReferencesOmitted: end - start - count, ClockKnown: known})
					}
				}
			}
			start = end
		}
	}
	after, e := fileSHA256Progress(path, "", 0, &verifyMeter{ctx: ctx})
	if e != nil {
		return result, e
	}
	if after != before {
		return result, errors.New("case index changed during temporal correlation")
	}
	result.Coverage = []Coverage{coverage("temporal_events", "events", int64(read), int64(read), 100000, !limited), coverage("temporal_groups", "groups", eligible, int64(len(result.Groups)), 2000, !limited)}
	result.Notes = append(result.Notes, "Examined "+strconv.Itoa(read)+" indexed event rows. Window groups are deterministic disjoint clusters anchored to their first displayed/estimated time; adjacent/overlapping windows are not exhaustively enumerated.")
	return result, nil
}
