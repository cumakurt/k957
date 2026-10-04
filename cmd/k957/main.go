package main

import (
	"context"
	"encoding/json"
	"flag"
	"fmt"
	"k957/internal/core"
	"os"
	"os/signal"
	"path/filepath"
	"strings"
	"time"
)

var exitProcess = os.Exit

func main() {
	if len(os.Args) == 2 && (os.Args[1] == "parser-worker" || os.Args[1] == "sqlite-backup-worker") {
		var e error
		if os.Args[1] == "parser-worker" {
			e = core.RunParserWorker(os.Stdin, os.Stdout)
		} else {
			e = core.RunSQLiteBackupWorker(os.Stdin, os.Stdout)
		}
		if e != nil {
			fmt.Fprintln(os.Stderr, "parser worker:", e)
			os.Exit(1)
		}
		return
	}
	go watchInterrupt()
	if e := run(os.Args[1:]); e != nil {
		fmt.Fprintln(os.Stderr, "k957:", e)
		exitProcess(1)
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
	case "case-bookmark":
		return runCaseSelection(args[1:])
	case "rules-evaluate":
		return runRuleCorpus(args[1:])
	case "custody-anchor":
		return runCustodyAnchor(args[1:])
	case "case-assistant", "assistant-review":
		return runAssistant(args[0], args[1:])
	case "source-import":
		return runSourceImport(args[1:])
	case "sqlite-acquire":
		return runSQLiteAcquire(args[1:])
	case "case-correlate":
		return runTemporal(args[1:])
	case "disk-examine", "disk-recover":
		return runDisk(args[0], args[1:])
	case "memory-examine":
		return runMemoryExamine(args[1:])
	case "version":
		fmt.Println("k957", core.Version)
		developerInfo()
		return nil
	case "build-info":
		return json.NewEncoder(os.Stdout).Encode(core.BuildInfo())
	case "help", "--help", "-h":
		help()
		return nil
	case "keygen":
		prefix := f.String("out", "", "new signing key prefix")
		if stop, e := parseFlags(f, args[1:]); stop || e != nil {
			return e
		}
		if *prefix == "" {
			return fmt.Errorf("out required")
		}
		return core.Keygen(*prefix)
	case "encryption-key":
		out := f.String("out", "", "new encryption key path")
		if stop, e := parseFlags(f, args[1:]); stop || e != nil {
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
		if stop, e := parseFlags(f, args[1:]); stop || e != nil {
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
		if stop, e := parseFlags(f, args[1:]); stop || e != nil {
			return e
		}
		ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt)
		defer stop()
		ctx, progress := attachProgress(ctx, "preflight", []progressPhase{{ID: "inventory", Weight: 1}})
		defer progress.finish()
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
		progress.done()
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
		if stop, e := parseFlags(f, args[1:]); stop || e != nil {
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
		if fullMode(args[1:]) {
			return runFullCollect(args[1:])
		}
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
		if stop, e := parseFlags(f, args[1:]); stop || e != nil {
			return e
		}
		ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt)
		defer stop()
		ctx, cancel := context.WithTimeout(ctx, *timeout)
		defer cancel()
		collectPhases := []progressPhase{{ID: "files", Weight: 9}, {ID: "package", Weight: 1}}
		if *work != "" || *checkSpace {
			collectPhases = []progressPhase{{ID: "inventory", Weight: 2}, {ID: "files", Weight: 7}, {ID: "package", Weight: 1}}
		}
		ctx, progress := attachProgress(ctx, "collect", collectPhases)
		defer progress.finish()
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
		progress.done()
		enc := json.NewEncoder(os.Stdout)
		if o.EncryptionKey != "" {
			if e = enc.Encode(map[string]any{"status": m.Status, "items": len(m.Items), "issues": len(m.Issues), "encrypted": true}); e != nil {
				return e
			}
		} else if e = enc.Encode(m); e != nil {
			return e
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
		if stop, e := parseFlags(f, args[1:]); stop || e != nil {
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
		return core.WriteJSONNew(*out, l)
	case "case":
		return runCase(args[1:])
	case "case-query", "case-serve":
		return runCaseAccess(args[0], args[1:])
	case "report-seal", "report-verify", "report-documents":
		return runReportCommand(args[0], args[1:])
	case "verify", "analyze", "share":
		in := f.String("in", "", "package path")
		store := f.String("store", "", "collection root; default ./output when --in is omitted")
		pub := f.String("trusted-key", "", "trusted signing public key")
		custody := f.String("custody", "", "signed custody ledger (analyze)")
		custodyTrust := f.String("custody-trust", "", "external actor/key trust JSON (analyze)")
		custodyHead := f.String("custody-head", "", "independently retained custody head (analyze)")
		out := f.String("out", "", "new report directory (analyze/share)")
		policy := f.String("policy", "", "share policy JSON; default masks all categories")
		reviews := f.String("reviews", "", "review ledger to apply after recomputing analysis")
		reviewKey := f.String("review-key", "", "trusted public key for review ledger")
		rules := f.String("rules", "", "literal/hash rule JSON (analyze)")
		hashSet := f.String("hash-set", "", "examiner SHA-256 set (analyze/share)")
		iocs := f.String("iocs", "", "offline k957-indicators/1 exact SHA-256, IP and domain list")
		if stop, e := parseFlags(f, args[1:]); stop || e != nil {
			return e
		}
		if *iocs != "" && args[0] == "verify" {
			return fmt.Errorf("iocs require analyze or share")
		}
		if *hashSet != "" && args[0] == "verify" {
			return fmt.Errorf("hash-set requires analyze or share")
		}
		if *policy != "" && args[0] != "share" {
			return fmt.Errorf("policy requires share command")
		}
		if *in == "" {
			if args[0] == "share" {
				return fmt.Errorf("share requires --in")
			}
			if *reviews != "" || *custody != "" || *custodyTrust != "" || *custodyHead != "" || *reviewKey != "" {
				return fmt.Errorf("reviews and custody apply to one package; pass --in")
			}
			root := *store
			if root == "" {
				root = "output"
			}
			if args[0] == "verify" {
				return runStoreVerify(root, *pub)
			}
			return runStoreAnalyzeWithIndicators(root, *rules, *pub, *hashSet, *iocs)
		}
		if *store != "" {
			return fmt.Errorf("store cannot be combined with --in")
		}
		phases := []progressPhase{{ID: "examine", Weight: 8}, {ID: "report", Weight: 2}}
		if args[0] == "verify" {
			phases = []progressPhase{{ID: "verify", Weight: 1}}
		} else if args[0] == "share" {
			phases = []progressPhase{{ID: "examine", Weight: 8}, {ID: "export", Weight: 2}}
		}
		ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt)
		defer stop()
		ctx, progress := attachProgress(ctx, args[0], phases)
		defer progress.finish()
		core.ReportProgress(ctx, core.Progress{Phase: phases[0].ID, Detail: *in, Step: 0, Steps: 1})
		p, e := core.OpenContext(ctx, *in, *pub)
		if e != nil {
			return e
		}
		defer p.Zip.Close()
		if args[0] == "verify" {
			if *custody != "" || *custodyTrust != "" || *custodyHead != "" {
				return fmt.Errorf("custody report flags require analyze; use custody-verify for verification")
			}
			core.ReportProgress(ctx, core.Progress{Phase: "verify", Detail: *in, Step: 1, Steps: 1})
			progress.done()
			return emitPackageVerification(*in, p.Signature, p.Manifest.Status, len(p.Manifest.Items), p.Manifest.Issues)
		}
		r, e := core.LoadRules(*rules)
		if e != nil {
			return e
		}
		ctx = parserContext(ctx)
		indicatorSet, e := core.LoadIndicators(*iocs)
		if e != nil {
			return e
		}
		ctx = core.WithIndicators(ctx, indicatorSet)
		workspace, e := os.MkdirTemp(filepath.Dir(*out), ".memory-analysis-")
		if e != nil {
			return e
		}
		defer os.RemoveAll(workspace)
		ctx = core.WithMemoryWorkspace(ctx, workspace)
		a := core.AnalyzeContext(ctx, p, r)
		if e := ctx.Err(); e != nil {
			return e
		}
		set, e := core.LoadHashSet(*hashSet)
		if e != nil {
			return e
		}
		core.ApplyHashSet(&a, set)
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
			core.ReportProgress(ctx, core.Progress{Phase: "export", Detail: *out, Step: 0, Steps: 1})
			shared, e := core.BuildSharedReport(a, policy)
			if e != nil {
				return e
			}
			if e = core.ExportShared(shared, *out); e != nil {
				return e
			}
			core.ReportProgress(ctx, core.Progress{Phase: "export", Detail: *out, Step: 1, Steps: 1})
			progress.done()
			fmt.Println("Shared report:", *out+"/report.html")
			fmt.Println("PDF:", *out+"/report.pdf")
			return nil
		}
		core.ReportProgress(ctx, core.Progress{Phase: "report", Detail: *out, Step: 0, Steps: 1})
		if e = core.ExportContext(ctx, a, *out); e != nil {
			return e
		}
		core.ReportProgress(ctx, core.Progress{Phase: "report", Detail: *out, Step: 1, Steps: 1})
		progress.done()
		fmt.Println("Report:", *out+"/report.html")
		fmt.Println("PDF:", *out+"/report.pdf")
		return nil
	}
	return fmt.Errorf("unknown command %q; use help", args[0])
}
func help() {
	fmt.Printf(`k957 %s — offline forensic triage, verification and examination
License: GNU AGPL-3.0-or-later. https://www.gnu.org/licenses/agpl-3.0.html
Developer: %s · %s
Repository: %s
LinkedIn: %s
Commands:
  wizard           interactive English collection / analysis assistant
  preflight        inspect inventory and estimated destination space without writing
  collect          collect files; with no arguments, run a full triage into ./output
  source-import    collect selected offline CloudTrail JSON/gzip exports with provenance
  sqlite-acquire   collect a separate transaction-consistent logical SQLite backup
  work-status      inspect resumable acquisition progress and verify parts
  verify           verify one package, or every collection under ./output
  analyze          report one package, or every collection under ./output
  case             examine every collection under ./output as one dossier
  case-query       search scoped events, findings, reviews and inventory
  case-assistant   select cited quotations and proposals with an explicit local model
  assistant-review record a separate signed examiner decision on an assistant proposal
  case-correlate   derive scoped temporal candidates with explicit clock estimates
  case-bookmark    save a signed investigation note and an explicitly covered query page
  case-serve       open a token-protected read-only loopback examiner UI
  rules-evaluate   retain true/false positive/negative counts for a labelled corpus
  report-seal      sign every derived report file and its source bindings
  report-verify    verify a report bundle with optional external signer trust
  report-documents generate native PDF/DOCX with source references and coverage
  disk-examine     examine a verified private raw-image copy using Sleuth Kit
  disk-recover     recover an explicitly scoped inode using Sleuth Kit
  memory-examine   enumerate kernel objects with recorded offline Volatility tools
  share            export a separate masked HTML/JSON/CSV report
  review           append an analyst decision to a new review ledger
  custody          append a signed custody declaration to a new ledger
  custody-anchor   sign a custody head for independent external retention
  custody-verify   verify every custody signature, actor, transition and head
  keygen           create Ed25519 .key/.pub signing key pair
  encryption-key   generate a random AES-256 transport key
  seal / unseal    encrypt/decrypt files in authenticated streaming frames
  version          show release version
  build-info       show compiler, target, pinned modules and source identity
Use k957 <command> -h for flags. Flag help exits 0. All explicit outputs must be new paths.
collect, preflight, verify, analyze, case and share write a live progress summary to stderr. It shows the phase, the current item, a percent when the amount of work is known, and an estimated remaining time. That summary is not stored as evidence. JSON results stay on stdout.
Ctrl+C stops the process immediately from any command or phase and exits 130. It does not finish the current file, seal a partial collection, or wait for a child command.
On a terminal, full collect, verify, analyze and case print a grouped summary. The complete collect record stays in collection.json. Piped stdout still receives JSON.
Examples:
  k957 collect
  k957 verify
  k957 analyze
  k957 case
  k957 collect --root ./evidence --out ./case.k957 --case CASE-1 --operator Analyst --scope "Approved directory"
  k957 analyze --in ./case.k957 --out ./report --rules ./examples/rules.json
`, core.Version, core.DeveloperName, core.DeveloperEmail, core.RepositoryURL, core.DeveloperLinkedIn)
}

func developerInfo() {
	fmt.Printf("Developer: %s · %s\nRepository: %s\nLinkedIn: %s\n", core.DeveloperName, core.DeveloperEmail, core.RepositoryURL, core.DeveloperLinkedIn)
}

func parseFlags(f *flag.FlagSet, args []string) (bool, error) {
	if e := f.Parse(args); e != nil {
		if e == flag.ErrHelp {
			return true, nil
		}
		return false, e
	}
	return false, nil
}

func fullMode(args []string) bool {
	if len(args) == 0 {
		return true
	}
	for _, a := range args {
		if a == "--full" || a == "-full" {
			return true
		}
	}
	return false
}

func runStoreVerify(root, trusted string) error {
	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt)
	defer stop()
	ctx, progress := attachProgress(ctx, "verify", []progressPhase{{ID: "verify", Weight: 1}})
	defer progress.finish()
	result, e := core.VerifyStore(ctx, root, trusted)
	if e != nil {
		progress.fail()
	}
	if result.Collections != nil {
		if e == nil {
			progress.done()
		}
		if ee := emitStoreVerification(result); ee != nil {
			return ee
		}
	}
	return e
}

func runCase(args []string) error {
	f := flag.NewFlagSet("case", flag.ContinueOnError)
	store := f.String("store", "", "collection root; default ./output")
	out := f.String("out", "", "new dossier directory; default ./case/<UTC timestamp>")
	hashes := f.String("hash-set", "", "examiner SHA-256 set")
	trusted := f.String("trusted-key", "", "trusted collection public key")
	rulesPath := f.String("rules", "", "literal or structured rule JSON; default built-in rules")
	iocs := f.String("iocs", "", "offline k957-indicators/1 exact indicator list")
	var reviews stringList
	f.Var(&reviews, "review", "review ledger for an examined collection; repeatable")
	reviewKey := f.String("review-key", "", "trusted review public key")
	if stop, e := parseFlags(f, args); stop || e != nil {
		return e
	}
	root := *store
	if root == "" {
		root = "output"
	}
	dest := *out
	if dest == "" {
		dest = filepath.Join("case", time.Now().UTC().Format("20060102T150405Z"))
	}
	set, e := core.LoadHashSet(*hashes)
	if e != nil {
		return e
	}
	rules, e := core.LoadRules(*rulesPath)
	if e != nil {
		return e
	}
	if *rulesPath == "" {
		rules = core.BuiltinRules()
	}
	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt)
	defer stop()
	ctx, progress := attachProgress(ctx, "case", []progressPhase{{ID: "case", Weight: 1}})
	defer progress.finish()
	indicatorSet, e := core.LoadIndicators(*iocs)
	if e != nil {
		return e
	}
	ctx = core.WithIndicators(ctx, indicatorSet)
	d, e := core.BuildCaseWithOptions(parserContext(ctx), root, dest, *trusted, set, core.CaseOptions{Rules: rules, ReviewPaths: reviews, ReviewKey: *reviewKey})
	if d.Directory != "" {
		progress.done()
		if ee := emitCase(d); ee != nil {
			return ee
		}
	}
	return e
}

func runStoreAnalyze(root, rules, trusted, hashSet string) error {
	return runStoreAnalyzeWithIndicators(root, rules, trusted, hashSet, "")
}
func runStoreAnalyzeWithIndicators(root, rules, trusted, hashSet, iocs string) error {
	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt)
	defer stop()
	ctx, progress := attachProgress(ctx, "analyze", []progressPhase{{ID: "analyze", Weight: 1}})
	defer progress.finish()
	indicatorSet, e := core.LoadIndicators(iocs)
	if e != nil {
		return e
	}
	ctx = core.WithIndicators(ctx, indicatorSet)
	result, e := core.AnalyzeStore(parserContext(ctx), root, rules, trusted, hashSet)
	if e != nil {
		progress.fail()
	}
	if result.Collections != nil {
		if e == nil {
			progress.done()
		}
		if ee := emitStoreAnalysis(result); ee != nil {
			return ee
		}
	}
	return e
}

func parserContext(ctx context.Context) context.Context {
	ctx = core.WithMemoryExamination(ctx, os.Getenv("K957_VOLATILITY"), os.Getenv("K957_MEMORY_SYMBOLS"), os.Getenv("K957_MEMORY_WORK_DIR"))
	executable, e := os.Executable()
	if e != nil {
		return ctx
	}
	return core.WithParserWorkers(ctx, executable)
}

type stringList []string

func (s *stringList) String() string { return strings.Join(*s, ",") }
func (s *stringList) Set(v string) error {
	*s = append(*s, v)
	return nil
}
