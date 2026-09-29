package main

import (
	"context"
	"encoding/json"
	"flag"
	"fmt"
	"k957/internal/core"
	"os"
	"os/signal"
	"time"
)

func main() {
	if e := run(os.Args[1:]); e != nil {
		fmt.Fprintln(os.Stderr, "k957:", e)
		os.Exit(1)
	}
}
func run(args []string) error {
	if len(args) == 0 {
		help()
		return nil
	}
	f := flag.NewFlagSet(args[0], flag.ContinueOnError)
	switch args[0] {
	case "wizard":
		return wizard()
	case "version":
		fmt.Println("k957", core.Version)
		return nil
	case "help", "--help", "-h":
		help()
		return nil
	case "keygen":
		prefix := f.String("out", "", "new signing key prefix")
		if e := f.Parse(args[1:]); e != nil {
			return e
		}
		if *prefix == "" {
			return fmt.Errorf("out required")
		}
		return core.Keygen(*prefix)
	case "encryption-key":
		out := f.String("out", "", "new encryption key path")
		if e := f.Parse(args[1:]); e != nil {
			return e
		}
		if *out == "" {
			return fmt.Errorf("out required")
		}
		return core.EncryptionKey(*out)
	case "seal", "unseal":
		in := f.String("in", "", "input file")
		out := f.String("out", "", "new output file")
		key := f.String("key", "", "AES-256 hex key file")
		if e := f.Parse(args[1:]); e != nil {
			return e
		}
		return core.Transform(*in, *out, *key, args[0] == "unseal")
	case "preflight":
		var o core.Options
		f.StringVar(&o.Root, "root", "", "source directory")
		f.StringVar(&o.Out, "out", "", "planned new output package")
		work := f.String("work", "", "staging directory (new, or existing with --resume)")
		resume := f.Bool("resume", false, "estimate remaining space from an existing checkpoint; use original root and limits")
		f.StringVar(&o.EncryptionKey, "encryption-key", "", "original key for an encrypted --resume checkpoint")
		encrypted := f.Bool("encrypted", false, "estimate encrypted resumable mode; does not read a key")
		reserve := f.Int64("reserve", 256<<20, "additional free-space reserve per target filesystem")
		f.Int64Var(&o.MaxFile, "max-file", 256<<20, "maximum bytes per source")
		f.Int64Var(&o.MaxTotal, "max-total", 2<<30, "maximum acquired bytes")
		f.IntVar(&o.MaxFiles, "max-files", 10000, "maximum source count")
		if e := f.Parse(args[1:]); e != nil {
			return e
		}
		ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt)
		defer stop()
		var result core.PreflightResult
		var e error
		if *resume {
			if *encrypted && o.EncryptionKey == "" {
				return fmt.Errorf("encrypted resume preflight requires the original encryption-key")
			}
			result, e = core.PreflightResume(ctx, o, *work, *reserve)
		} else {
			if o.EncryptionKey != "" {
				return fmt.Errorf("encryption-key requires resume; use encrypted for fresh estimates")
			}
			result, e = core.Preflight(ctx, o, *work, *encrypted, *reserve)
		}
		if e != nil {
			return e
		}
		if e := json.NewEncoder(os.Stdout).Encode(result); e != nil {
			return e
		}
		if result.Outcome == "blocked" || result.Outcome == "unknown" {
			return fmt.Errorf("preflight %s; see JSON checks", result.Outcome)
		}
		return nil
	case "work-status":
		work := f.String("work", "", "staging directory")
		encryptionKey := f.String("encryption-key", "", "key for encrypted staging")
		verify := f.Bool("verify-parts", false, "rehash saved parts (does not inspect source)")
		if e := f.Parse(args[1:]); e != nil {
			return e
		}
		ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt)
		defer stop()
		status, e := core.InspectWork(ctx, *work, *verify, *encryptionKey)
		if e != nil {
			return e
		}
		return json.NewEncoder(os.Stdout).Encode(status)
	case "collect":
		var o core.Options
		f.StringVar(&o.Root, "root", "", "directory to collect recursively")
		f.StringVar(&o.Out, "out", "", "new .k957 package outside source tree")
		f.StringVar(&o.Case, "case", "", "case identifier")
		f.StringVar(&o.Operator, "operator", "", "operator name")
		f.StringVar(&o.Scope, "scope", "", "authorized collection scope")
		f.StringVar(&o.EncryptionKey, "encryption-key", "", "encrypt staging and final output; requires --work")
		f.StringVar(&o.SignKey, "sign-key", "", "optional Ed25519 private key file")
		work := f.String("work", "", "resumable staging directory outside source/output (logical files only)")
		resume := f.Bool("resume", false, "resume an existing --work with identical scope and limits")
		f.BoolVar(&o.System, "system", false, "opt-in live system snapshots")
		f.Int64Var(&o.MaxFile, "max-file", 256<<20, "maximum bytes per source")
		f.Int64Var(&o.MaxTotal, "max-total", 2<<30, "maximum acquired bytes")
		f.IntVar(&o.MaxFiles, "max-files", 10000, "maximum source count")
		checkSpace := f.Bool("check-space", false, "run preflight before a fresh or resumed logical acquisition")
		reserve := f.Int64("reserve", 256<<20, "space reserve used by --check-space")
		timeout := f.Duration("timeout", 30*time.Minute, "collection deadline")
		if e := f.Parse(args[1:]); e != nil {
			return e
		}
		ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt)
		defer stop()
		ctx, cancel := context.WithTimeout(ctx, *timeout)
		defer cancel()
		if *checkSpace {
			var result core.PreflightResult
			var e error
			if *resume {
				result, e = core.PreflightResume(ctx, o, *work, *reserve)
			} else {
				result, e = core.Preflight(ctx, o, *work, o.EncryptionKey != "", *reserve)
			}
			if e != nil {
				return e
			}
			if result.Outcome == "blocked" || result.Outcome == "unknown" {
				return fmt.Errorf("preflight %s; run preflight for detailed checks", result.Outcome)
			}
			fmt.Fprintln(os.Stderr, "preflight:", result.Outcome)
		}
		var m core.Manifest
		var e error
		if *resume && *work == "" {
			return fmt.Errorf("resume requires work directory")
		}
		if *work != "" {
			m, e = core.CollectResumable(ctx, o, *work, *resume)
		} else {
			m, e = core.Collect(ctx, o)
		}
		if e != nil {
			return e
		}
		if o.EncryptionKey != "" {
			json.NewEncoder(os.Stdout).Encode(map[string]any{"status": m.Status, "items": len(m.Items), "issues": len(m.Issues), "encrypted": true})
		} else {
			json.NewEncoder(os.Stdout).Encode(m)
		}
		if m.Status != "complete" {
			return fmt.Errorf("partial collection saved; review manifest issues")
		}
		return nil
	case "custody", "custody-verify":
		return runCustody(args)
	case "review":
		analysis := f.String("analysis", "", "original analysis.json from current version")
		previous := f.String("previous", "", "previous review ledger, if any")
		finding := f.String("finding", "", "stable finding ID")
		decision := f.String("decision", "", "confirmed, rejected or needs-review")
		analyst := f.String("analyst", "", "analyst name")
		note := f.String("note", "", "required reason")
		out := f.String("out", "", "new review ledger JSON")
		sign := f.String("sign-key", "", "optional signing private key")
		previousKey := f.String("previous-key", "", "trusted public key for previous signed ledger")
		if e := f.Parse(args[1:]); e != nil {
			return e
		}
		a, e := core.LoadAnalysis(*analysis)
		if e != nil {
			return e
		}
		var prev *core.ReviewLedger
		if *previous != "" {
			l, e := core.LoadLedger(*previous)
			if e != nil {
				return e
			}
			prev = &l
		}
		l, e := core.AddReview(a, prev, *finding, *decision, *analyst, *note, *sign, *previousKey)
		if e != nil {
			return e
		}
		return core.WriteNew(*out, core.JSON(l))
	case "verify", "analyze", "share":
		in := f.String("in", "", "package path")
		pub := f.String("trusted-key", "", "trusted signing public key")
		custody := f.String("custody", "", "signed custody ledger (analyze)")
		custodyTrust := f.String("custody-trust", "", "external actor/key trust JSON (analyze)")
		custodyHead := f.String("custody-head", "", "independently retained custody head (analyze)")
		out := f.String("out", "", "new report directory (analyze/share)")
		policy := f.String("policy", "", "share policy JSON; default masks all categories")
		reviews := f.String("reviews", "", "review ledger to apply after recomputing analysis")
		reviewKey := f.String("review-key", "", "trusted public key for review ledger")
		rules := f.String("rules", "", "literal/hash rule JSON (analyze)")
		if e := f.Parse(args[1:]); e != nil {
			return e
		}
		if *policy != "" && args[0] != "share" {
			return fmt.Errorf("policy requires share command")
		}
		p, e := core.Open(*in, *pub)
		if e != nil {
			return e
		}
		defer p.Zip.Close()
		if args[0] == "verify" {
			if *custody != "" || *custodyTrust != "" || *custodyHead != "" {
				return fmt.Errorf("custody report flags require analyze; use custody-verify for verification")
			}
			return json.NewEncoder(os.Stdout).Encode(map[string]any{"integrity": "verified", "signature": p.Signature, "collection_status": p.Manifest.Status, "items": len(p.Manifest.Items), "issues": p.Manifest.Issues})
		}
		r, e := core.LoadRules(*rules)
		if e != nil {
			return e
		}
		a := core.Analyze(p, r)
		if *reviews != "" {
			l, e := core.LoadLedger(*reviews)
			if e != nil {
				return e
			}
			if e = core.ApplyReviews(&a, l, *reviewKey); e != nil {
				return e
			}
		} else if *reviewKey != "" {
			return fmt.Errorf("review-key requires reviews")
		}
		if *custody != "" {
			l, e := core.LoadCustody(*custody)
			if e != nil {
				return e
			}
			t, e := core.LoadCustodyTrust(*custodyTrust)
			if e != nil {
				return e
			}
			if e = core.ApplyCustody(&a, l, t, *custodyHead); e != nil {
				return e
			}
		} else if *custodyTrust != "" || *custodyHead != "" {
			return fmt.Errorf("custody-trust and custody-head require custody")
		}
		if args[0] == "share" {
			policy, e := core.LoadSharePolicy(*policy)
			if e != nil {
				return e
			}
			shared, e := core.BuildSharedReport(a, policy)
			if e != nil {
				return e
			}
			if e = core.ExportShared(shared, *out); e != nil {
				return e
			}
			fmt.Println("Shared report:", *out+"/report.html")
			return nil
		}
		if e = core.Export(a, *out); e != nil {
			return e
		}
		fmt.Println("Report:", *out+"/report.html")
		return nil
	}
	return fmt.Errorf("unknown command %q; use help", args[0])
}
func help() {
	fmt.Println(`k957 0.9.0 — portable evidence collection and analysis
Commands:
  wizard           interactive Turkish collection / analysis assistant
  preflight        inspect inventory and estimated destination space without writing
  collect          collect selected files and optional live system snapshots
  work-status      inspect resumable acquisition progress and verify parts
  verify           verify all package objects and optional trusted signature
  analyze          create HTML report, JSON analysis and CSV timeline
  share            export a separate masked HTML/JSON/CSV report
  review           append an analyst decision to a new review ledger
  custody          append a signed custody declaration to a new ledger
  custody-verify   verify every custody signature, actor, transition and head
  keygen           create Ed25519 .key/.pub signing key pair
  encryption-key   generate a random AES-256 transport key
  seal / unseal    encrypt/decrypt files in authenticated streaming frames
  version          show release version
Use k957 <command> -h for flags. All outputs must be new paths.
Example:
  k957 collect --root ./evidence --out ./case.k957 --case CASE-1 --operator Analyst --scope "Approved directory"
  k957 analyze --in ./case.k957 --out ./report --rules ./examples/rules.json`)
}
