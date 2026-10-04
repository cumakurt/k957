package core

import (
	"context"
	"testing"
)

func TestRuleCorpusAccuracyAndInvalidLabels(t *testing.T) {
	rules := []Rule{{ID: "admin", Event: &EventRule{All: []FieldCondition{{Field: "user", Op: "equals", Value: "admin"}}}}}
	c := RuleCorpus{Schema: "k957-rule-corpus/1", Name: "synthetic confusion matrix", Events: []Event{{User: "admin"}, {User: "admin"}, {User: "other"}, {User: "other"}}, Positive: []RuleLabel{{"admin", 0}, {"admin", 2}}}
	r, err := EvaluateRuleCorpus(context.Background(), rules, c)
	if err != nil {
		t.Fatal(err)
	}
	m := r.Metrics[0]
	if m.TP != 1 || m.FP != 1 || m.FN != 1 || m.TN != 1 || *m.Precision != 0.5 || *m.Recall != 0.5 {
		t.Fatal(m)
	}
	c.Positive = append(c.Positive, c.Positive[0])
	if _, err = EvaluateRuleCorpus(context.Background(), rules, c); err == nil {
		t.Fatal("duplicate labels accepted")
	}
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	c.Positive = nil
	if _, err = EvaluateRuleCorpus(ctx, rules, c); err == nil {
		t.Fatal("cancelled evaluation published")
	}
}
