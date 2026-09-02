// Package web holds the page a person looks at, and embeds it.
//
// The files are hand-written HTML, CSS and ES modules with no build step, and they are
// embedded exactly as they are written (ADR-0022 §3). There is no bundler, no lockfile and
// no Node in CI or in the release job — which is a saving worth having while the view is
// one page answering one question, and stops being one at a size that decision does not
// try to predict.
//
// The embed directive lives here, beside the files, because a go:embed pattern cannot
// reach upward out of its own directory — the same constraint that puts one in the
// migrations package rather than in internal/store.
package web

import "embed"

// FS holds the page. Only the named files are embedded, so this source file and anything
// else that lands in this directory is not served by accident.
//
// That safety has a cost worth knowing about: a new file is not served until it is added
// here, and nothing fails at build time when it is missing. web/testdata/fixture.py serves
// this directory from disk, so a page split across a new module works perfectly against the
// fixture and 404s in the real binary. dom.js was added in exactly that way.
//
//go:embed index.html app.css app.js dom.js
var FS embed.FS
