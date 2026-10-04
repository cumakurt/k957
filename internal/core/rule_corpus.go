package core

import (
	"context"
	"errors"
	"fmt"
)

type RuleLabel struct {
	Rule       string `json:"rule"`
	EventIndex int    `json:"event_index"`
}
type RuleCorpus struct {
	Schema   string      `json:"schema"`
	Name     string      `json:"name"`
	Events   []Event     `json:"events"`
	Positive []RuleLabel `json:"positive"`
}
type RuleAccuracy struct {
	Rule      string   `json:"rule"`
	TP        int      `json:"true_positive"`
	FP        int      `json:"false_positive"`
	FN        int      `json:"false_negative"`
	TN        int      `json:"true_negative"`
	Precision *float64 `json:"precision,omitempty"`
	Recall    *float64 `json:"recall,omitempty"`
}
type RuleCorpusResult struct {
	Schema       string         `json:"schema"`
	CorpusSHA256 string         `json:"corpus_sha256"`
	RulesSHA256  string         `json:"rules_sha256"`
	Name         string         `json:"name"`
	Events       int            `json:"events"`
	Metrics      []RuleAccuracy `json:"metrics"`
	Notes        []string       `json:"notes"`
}

func EvaluateRuleCorpus(ctx context.Context, rules []Rule, corpus RuleCorpus) (result RuleCorpusResult, err error) {
	if corpus.Schema != "k957-rule-corpus/1" || !custodyText(corpus.Name, 256, false) || len(corpus.Events) == 0 || len(corpus.Events) > 10000 || len(corpus.Positive) > 100000 || len(rules) == 0 || len(rules) > 100 {
		return result, errors.New("invalid rule corpus/pack bounds")
	}
	ruleIDs := map[string]bool{}
	for _, rule := range rules {
		if rule.Event == nil || rule.Contains != "" || rule.SHA256 != "" || !custodyText(rule.ID, 256, false) || ruleIDs[rule.ID] {
			return result, errors.New("corpus runner requires unique structured event rules only")
		}
		ruleIDs[rule.ID] = true
	}
	labels := map[string]bool{}
	for _, label := range corpus.Positive {
		key := fmt.Sprint(label.EventIndex) + "/" + label.Rule
		if !ruleIDs[label.Rule] || label.EventIndex < 0 || label.EventIndex >= len(corpus.Events) || labels[key] {
			return result, errors.New("invalid or duplicate corpus label")
		}
		labels[key] = true
	}
	result = RuleCorpusResult{Schema: "k957-rule-evaluation/1", CorpusSHA256: digestJSON(corpus), RulesSHA256: digestJSON(rules), Name: corpus.Name, Events: len(corpus.Events), Metrics: []RuleAccuracy{}, Notes: []string{"Metrics apply only to supplied event projections and examiner labels. Unlisted event/rule pairs are labelled negative by this closed-world corpus contract.", "Digests bind decoded, strictly loaded corpus/rule JSON projections. Results do not establish acquisition/parser correctness or production detection accuracy. Undefined precision/recall is omitted, not zero."}}
	for _, rule := range rules {
		all, any, err := prepareEventRule(*rule.Event)
		if err != nil {
			return result, err
		}
		metric := RuleAccuracy{Rule: rule.ID}
		for index, event := range corpus.Events {
			if err := ctx.Err(); err != nil {
				return result, err
			}
			predicted := eventRuleMatches(event, all, any)
			expected := labels[fmt.Sprint(index)+"/"+rule.ID]
			switch {
			case predicted && expected:
				metric.TP++
			case predicted:
				metric.FP++
			case expected:
				metric.FN++
			default:
				metric.TN++
			}
		}
		if metric.TP+metric.FP > 0 {
			p := float64(metric.TP) / float64(metric.TP+metric.FP)
			metric.Precision = &p
		}
		if metric.TP+metric.FN > 0 {
			r := float64(metric.TP) / float64(metric.TP+metric.FN)
			metric.Recall = &r
		}
		result.Metrics = append(result.Metrics, metric)
	}
	return result, nil
}

func LoadRuleCorpus(path string) (corpus RuleCorpus, err error) {
	err = strictJSON(path, 32<<20, &corpus)
	return
}
