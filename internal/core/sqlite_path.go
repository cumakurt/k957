package core

import (
	"net/url"
	"path/filepath"
	"strings"
)

// SQLite file URIs need an absolute URL path. Without the leading slash,
// net/url serializes a Windows drive as the authority (file://C:/...).
func sqliteFileURL(absolutePath string) url.URL {
	path := filepath.ToSlash(absolutePath)
	if !strings.HasPrefix(path, "/") {
		path = "/" + path
	}
	return url.URL{Scheme: "file", Path: path}
}
