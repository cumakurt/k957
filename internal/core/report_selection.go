package core

import (
	"bytes"
	"html/template"
)

func writeSelectionHTML(s CaseSelection, rows []documentParagraph, path string) error {
	t, e := template.New("selection").Parse(`<!doctype html><html lang="en"><meta charset="utf-8"><meta name="viewport" content="width=device-width"><title>k957 · {{.Selection.Title}}</title><style>` + reportStyle + `</style><main><header><small>k957 / selected examination record</small><h1>{{.Selection.Title}}</h1><p>{{.Selection.Analyst}} · {{.Selection.Created}}</p><p class="reading-edition"><a href="report.pdf">PDF reading edition</a> · <a href="selection.json">Full selected records</a> · <a href="documents.json">Document coverage</a></p></header>{{range .Rows}}{{if .Heading}}<h2>{{.Text}}</h2>{{else}}<p><code>{{.Text}}</code></p>{{end}}{{end}}<footer>Derived query page. Check its coverage, source index hash and bundle signature before relying on a row.</footer></main></html>`)
	if e != nil {
		return e
	}
	var b bytes.Buffer
	if e = t.Execute(&b, struct {
		Selection CaseSelection
		Rows      []documentParagraph
	}{s, rows}); e != nil {
		return e
	}
	return WriteNew(path, b.Bytes())
}
