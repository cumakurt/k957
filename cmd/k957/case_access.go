package main

import (
	"context"
	"crypto/rand"
	"crypto/sha256"
	"crypto/subtle"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"k957/internal/core"
	"net"
	"net/http"
	"net/url"
	"os"
	"os/signal"
	"path/filepath"
	"strconv"
	"time"
)

func parseCaseQuery(values url.Values) (core.CaseQuery, error) {
	q := core.CaseQuery{Kind: values.Get("kind"), Host: values.Get("host"), Evidence: values.Get("evidence"), Digest: values.Get("digest"), Text: values.Get("text"), Limit: 100}
	q.NativeParser, q.NativeRecord, q.USNFileID = values.Get("native-parser"), values.Get("native-record"), values.Get("usn-file-id")
	var e error
	if v := values.Get("limit"); v != "" {
		q.Limit, e = strconv.Atoi(v)
		if e != nil {
			return q, errors.New("invalid limit")
		}
	}
	if v := values.Get("offset"); v != "" {
		q.Offset, e = strconv.Atoi(v)
		if e != nil {
			return q, errors.New("invalid offset")
		}
	}
	for _, pair := range []struct {
		name string
		dest **time.Time
	}{{"after", &q.After}, {"before", &q.Before}} {
		if v := values.Get(pair.name); v != "" {
			stamp, e := time.Parse(time.RFC3339Nano, v)
			if e != nil {
				return q, fmt.Errorf("%s must be RFC3339", pair.name)
			}
			*pair.dest = &stamp
		}
	}
	return q, nil
}

func runCaseAccess(command string, args []string) error {
	f := flag.NewFlagSet(command, flag.ContinueOnError)
	dir := f.String("case", "", "derived case directory")
	text := f.String("text", "", "literal substring search")
	kind := f.String("kind", "", "event, finding, review, inventory, activity, indicator_match, memory_observation or boundary")
	host := f.String("host", "", "exact collection host")
	digest := f.String("digest", "", "exact signed collection SHA-256")
	evidence := f.String("evidence", "", "exact evidence ID, scoped by --digest")
	nativeParser := f.String("native-parser", "", "exact native parser name; event rows only")
	nativeRecord := f.String("native-record", "", "exact native record ID; event rows only")
	usnFileID := f.String("usn-file-id", "", "exact USN file ID in raw little-endian hex; event rows only")
	after := f.String("after", "", "inclusive RFC3339 lower time bound")
	before := f.String("before", "", "inclusive RFC3339 upper time bound")
	limit := f.Int("limit", 100, "page size, 1..200")
	offset := f.Int("offset", 0, "row offset")
	port := f.Int("port", 0, "loopback viewer port; 0 selects an available port")
	if stop, e := parseFlags(f, args); stop || e != nil {
		return e
	}
	if *dir == "" {
		return errors.New("case directory required")
	}
	path := filepath.Join(*dir, "case-index.sqlite")
	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt)
	defer stop()
	if command == "case-serve" {
		return serveCase(ctx, path, *port)
	}
	values := url.Values{"text": {*text}, "kind": {*kind}, "host": {*host}, "digest": {*digest}, "evidence": {*evidence}, "after": {*after}, "before": {*before}, "limit": {strconv.Itoa(*limit)}, "offset": {strconv.Itoa(*offset)}}
	values.Set("native-parser", *nativeParser)
	values.Set("native-record", *nativeRecord)
	values.Set("usn-file-id", *usnFileID)
	q, e := parseCaseQuery(values)
	if e != nil {
		return e
	}
	page, e := core.QueryCase(ctx, path, q)
	if e != nil {
		return e
	}
	return json.NewEncoder(os.Stdout).Encode(page)
}

func caseViewerHandler(path, authority, token string) http.Handler {
	gate := make(chan struct{}, 4)
	hash := sha256.Sum256([]byte(caseViewerScript))
	csp := "default-src 'none'; script-src 'sha256-" + base64.StdEncoding.EncodeToString(hash[:]) + "'; style-src 'unsafe-inline'; connect-src 'self'; base-uri 'none'; frame-ancestors 'none'; form-action 'self'"
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Cache-Control", "no-store")
		w.Header().Set("Content-Security-Policy", csp)
		w.Header().Set("X-Content-Type-Options", "nosniff")
		w.Header().Set("Referrer-Policy", "no-referrer")
		if r.Host != authority || len(r.URL.RawQuery) > 2048 || (r.Header.Get("Origin") != "" && r.Header.Get("Origin") != "http://"+authority) {
			http.Error(w, "forbidden", http.StatusForbidden)
			return
		}
		if r.Method != http.MethodGet && r.Method != http.MethodHead {
			http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
			return
		}
		provided := r.URL.Query().Get("token")
		if subtle.ConstantTimeCompare([]byte(provided), []byte(token)) != 1 {
			http.Error(w, "forbidden", http.StatusForbidden)
			return
		}
		switch r.URL.Path {
		case "/":
			w.Header().Set("Content-Type", "text/html; charset=utf-8")
			if r.Method != http.MethodHead {
				fmt.Fprint(w, caseViewerPage)
			}
		case "/api/rows":
			select {
			case gate <- struct{}{}:
				defer func() { <-gate }()
			default:
				http.Error(w, "busy", http.StatusServiceUnavailable)
				return
			}
			q, e := parseCaseQuery(r.URL.Query())
			if e != nil {
				http.Error(w, e.Error(), http.StatusBadRequest)
				return
			}
			page, e := core.QueryCase(r.Context(), path, q)
			if e != nil {
				http.Error(w, "case query failed or bounds are invalid", http.StatusBadRequest)
				return
			}
			w.Header().Set("Content-Type", "application/json")
			if r.Method != http.MethodHead {
				json.NewEncoder(w).Encode(page)
			}
		default:
			http.NotFound(w, r)
		}
	})
}

func serveCase(ctx context.Context, path string, port int) error {
	if port < 0 || port > 65535 {
		return errors.New("invalid loopback port")
	}
	if _, e := core.QueryCase(ctx, path, core.CaseQuery{Limit: 1}); e != nil {
		return e
	}
	listener, e := net.Listen("tcp4", net.JoinHostPort("127.0.0.1", strconv.Itoa(port)))
	if e != nil {
		return e
	}
	defer listener.Close()
	secret := make([]byte, 32)
	if _, e = rand.Read(secret); e != nil {
		return e
	}
	authority := listener.Addr().String()
	token := hex.EncodeToString(secret)
	srv := &http.Server{Handler: caseViewerHandler(path, authority, token), ReadHeaderTimeout: 5 * time.Second, ReadTimeout: 10 * time.Second, WriteTimeout: 10 * time.Second, IdleTimeout: 30 * time.Second, MaxHeaderBytes: 8192}
	done := make(chan error, 1)
	go func() { done <- srv.Serve(listener) }()
	fmt.Println("Read-only case viewer: http://" + authority + "/?token=" + token)
	fmt.Println("Press Ctrl+C to stop. The index is derived; verify cited signed collections before conclusions.")
	select {
	case e = <-done:
		if errors.Is(e, http.ErrServerClosed) {
			return nil
		}
		return e
	case <-ctx.Done():
		stopCtx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
		defer cancel()
		return srv.Shutdown(stopCtx)
	}
}

const caseViewerScript = `
"use strict";
const token=new URLSearchParams(location.search).get("token");let offset=0;const limit=100;
const $=id=>document.getElementById(id);let requestID=0,controller,filters=new URLSearchParams();
const filterFields=["kind","text","host","digest","evidence","native-parser","native-record","usn-file-id","after","before"];
function search(){filters=new URLSearchParams();for(const id of filterFields){if($(id).value)filters.set(id,$(id).value)}offset=0;load()}
async function load(){
 const id=++requestID;if(controller)controller.abort();controller=new AbortController();
 const q=new URLSearchParams({token,limit:String(limit),offset:String(offset)});
 for(const [key,value] of filters)q.set(key,value);
 $("status").textContent="Loading…";$("next").disabled=true;$("prev").disabled=true;$("rows").replaceChildren();$("detail").textContent="Select a row.";
 try{
  const response=await fetch("/api/rows?"+q,{cache:"no-store",signal:controller.signal});if(!response.ok)throw new Error(await response.text());const page=await response.json();if(id!==requestID)return;offset=page.offset;
  $("rows").replaceChildren();for(const row of page.rows){const tr=document.createElement("tr");for(const key of ["kind","time","host","collection_digest","evidence","source"]){const td=document.createElement("td");td.textContent=row[key]||"";tr.append(td)}
   const td=document.createElement("td"),b=document.createElement("button");b.textContent="Open reference";b.onclick=()=>{$("detail").textContent=JSON.stringify(row,null,2);$("detail").focus()};td.append(b);
   const fileID=row.payload&&row.payload.usn&&row.payload.usn.file_id_le_hex;
   if(typeof fileID==="string"&&/^(?:[0-9a-fA-F]{16}|[0-9a-fA-F]{32})$/.test(fileID)){const related=document.createElement("button");related.textContent="Related file records";related.onclick=()=>{for(const id of filterFields)$(id).value="";$("kind").value="event";$("digest").value=row.collection_digest;$("evidence").value=row.evidence;$("usn-file-id").value=fileID;search()};td.append(related)}
   tr.append(td);$("rows").append(tr)}
  $("status").textContent=page.rows.length+" rows · offset "+offset;$("next").disabled=!page.more;$("prev").disabled=offset===0;
 }catch(e){if(id===requestID&&e.name!=="AbortError")$("status").textContent=e.message}
}
$("search").onsubmit=e=>{e.preventDefault();search()};$("next").onclick=()=>{offset+=limit;load()};$("prev").onclick=()=>{offset=Math.max(0,offset-limit);load()};load();
`

const caseViewerPage = `<!doctype html><html lang="en"><head><meta charset="utf-8"><meta name="viewport" content="width=device-width,initial-scale=1"><title>k957 case examination</title><style>
body{font:15px system-ui;margin:24px;background:#f4f6f9;color:#1c2738}h1{font-size:26px}form{display:flex;flex-wrap:wrap;gap:12px;background:white;padding:16px;border-radius:8px}label{display:grid;gap:5px}input,select,button{font:inherit;padding:8px;border:1px solid #b5c0cf;border-radius:4px}button{cursor:pointer;background:#eaf0fc}td button{display:block;margin:4px 0}input{max-width:220px}.table{overflow:auto;background:white;margin-top:16px}table{border-collapse:collapse;width:100%;font-size:13px}th,td{padding:10px;border-bottom:1px solid #ddd;text-align:left;max-width:260px;overflow-wrap:anywhere}pre{white-space:pre-wrap;overflow-wrap:anywhere;background:#182335;color:#e4edf9;padding:16px;min-height:120px}p{max-width:960px;line-height:1.5}
</style></head><body><h1>Case examination</h1><p>Read-only derived index. Each evidence ID is scoped by its signed collection digest. Open a reference to inspect original event, finding or review fields. Verify the signed collection before adopting a conclusion. A shared host or timestamp does not establish attribution or causality.</p>
<form id="search"><label>Record kind<select id="kind"><option value="">All</option><option>event</option><option>finding</option><option>review</option><option>inventory</option><option>activity</option><option>memory_observation</option><option>indicator_match</option><option>boundary</option></select></label><label>Literal text<input id="text" maxlength="256"></label><label>Collection host<input id="host" maxlength="256"></label><label>Collection SHA-256<input id="digest" maxlength="64"></label><label>Evidence ID<input id="evidence" maxlength="256"></label><label>Native parser (exact)<input id="native-parser" maxlength="64" placeholder="USN"></label><label>Native record (exact)<input id="native-record" maxlength="256"></label><label>USN file ID (raw LE hex)<input id="usn-file-id" maxlength="32" pattern="[0-9a-fA-F]{16}([0-9a-fA-F]{16})?"></label><label>After (RFC3339)<input id="after" placeholder="2024-01-01T00:00:00Z"></label><label>Before (RFC3339)<input id="before"></label><button type="submit">Search</button></form>
<p>Native reference filters select event rows. Use All or event as the record kind. Combine collection SHA-256 and evidence ID to scope a file or record; equal IDs in different collections do not establish identity.</p>
<p id="status" role="status"></p><button id="prev">Previous</button> <button id="next">Next</button><div class="table"><table><thead><tr><th>Kind</th><th>UTC</th><th>Host</th><th>Collection digest</th><th>Evidence</th><th>Source</th><th>Reference</th></tr></thead><tbody id="rows"></tbody></table></div><h2>Selected reference</h2><pre id="detail" tabindex="0">Select a row.</pre><script>` + caseViewerScript + `</script></body></html>`
