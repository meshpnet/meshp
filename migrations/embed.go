// Package migrations embeds the SQL schema so meshp-control can apply it
// without needing the files on disk beside the binary.
//
// The .sql files stay at the top level of the repository rather than under
// internal/, because they are read by people and by tooling far more often than
// by Go: psql, the migrate-check script, and anyone auditing the schema before
// trusting the project with their network. A go:embed directive cannot reach
// upward out of its own directory, so the embedding lives here with them.
package migrations

import "embed"

// FS holds every migration, in filename order.
//
//go:embed *.sql
var FS embed.FS
