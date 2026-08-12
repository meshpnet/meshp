package store

import (
	"os"
	"path/filepath"
	"regexp"
	"strings"
	"testing"
)

// The multi-tenancy failure mode in a system like this is not a clever attack. It
// is a forgotten WHERE clause: a query written to list one network's devices that
// lists every network's devices, returning correct-looking results in development
// where there is only one tenant, and leaking across customers in production.
//
// Rather than hoping review catches it, every read query must either constrain
// itself with a bound parameter or say out loud that it is deliberately global.
// This runs without a database, so it gates every pull request.
var (
	queryNamePattern = regexp.MustCompile(`(?m)^--\s*name:\s*(\S+)\s+(\S+)\s*$`)
	globalScopeOptIn = regexp.MustCompile(`(?m)^--\s*scope:\s*global\s*(\S.*)$`)
)

func TestEveryReadQueryIsScopedToATenant(t *testing.T) {
	dir := queriesDir(t)
	entries, err := filepath.Glob(filepath.Join(dir, "*.sql"))
	if err != nil {
		t.Fatal(err)
	}
	if len(entries) == 0 {
		t.Fatalf("no query files found in %s", dir)
	}

	checked := 0
	for _, path := range entries {
		body, err := os.ReadFile(path)
		if err != nil {
			t.Fatal(err)
		}
		name := filepath.Base(path)

		for _, q := range splitQueries(string(body)) {
			checked++
			t.Run(name+"/"+q.name, func(t *testing.T) {
				verb := statementVerb(q.sql)

				// Writes cannot leak another tenant's rows by omission; a missing
				// predicate on a write is a correctness bug that other tests catch.
				if verb == "INSERT" {
					return
				}

				if m := globalScopeOptIn.FindStringSubmatch(q.sql); m != nil {
					// Deliberately global is fine, but it has to be a decision with a
					// stated reason rather than an oversight.
					if strings.TrimSpace(m[1]) == "" {
						t.Errorf("%s opts out of tenant scoping with no reason given;\n"+
							"write '-- scope: global <why>'", q.name)
					}
					return
				}

				where := whereClause(q.sql)
				if where == "" {
					t.Errorf("%s is a %s with no WHERE clause.\n"+
						"Add a tenant predicate, or declare '-- scope: global <why>' if that is intended.\n%s",
						q.name, verb, indent(q.sql))
					return
				}
				if !strings.Contains(where, "$") {
					t.Errorf("%s has a WHERE clause with no bound parameter, so it cannot be\n"+
						"constrained to a caller's tenant. Add one, or declare '-- scope: global <why>'.\n%s",
						q.name, indent(where))
				}
			})
		}
	}

	if checked == 0 {
		t.Fatal("no queries were checked; the parser is not finding any")
	}
	t.Logf("checked %d queries across %d files", checked, len(entries))
}

type namedQuery struct {
	name string
	sql  string
}

// splitQueries breaks a sqlc query file into its annotated blocks.
func splitQueries(body string) []namedQuery {
	locs := queryNamePattern.FindAllStringSubmatchIndex(body, -1)
	out := make([]namedQuery, 0, len(locs))
	for i, loc := range locs {
		end := len(body)
		if i+1 < len(locs) {
			end = locs[i+1][0]
		}
		out = append(out, namedQuery{
			name: body[loc[2]:loc[3]],
			sql:  body[loc[1]:end],
		})
	}
	return out
}

// statementVerb reports the leading keyword, ignoring comments and blank lines.
func statementVerb(sql string) string {
	for _, line := range strings.Split(sql, "\n") {
		line = strings.TrimSpace(line)
		if line == "" || strings.HasPrefix(line, "--") {
			continue
		}
		fields := strings.Fields(strings.ToUpper(line))
		if len(fields) == 0 {
			continue
		}
		if fields[0] == "WITH" {
			continue // a CTE; keep looking for the statement it feeds
		}
		return fields[0]
	}
	return "UNKNOWN"
}

// whereClause returns everything from the first WHERE onward, with comments
// stripped so a predicate mentioned only in prose does not count.
func whereClause(sql string) string {
	var b strings.Builder
	for _, line := range strings.Split(sql, "\n") {
		if i := strings.Index(line, "--"); i >= 0 {
			line = line[:i]
		}
		b.WriteString(line)
		b.WriteString("\n")
	}
	stripped := b.String()

	idx := regexp.MustCompile(`(?i)\bWHERE\b`).FindStringIndex(stripped)
	if idx == nil {
		return ""
	}
	return stripped[idx[0]:]
}

func indent(s string) string {
	lines := strings.Split(strings.TrimSpace(s), "\n")
	for i, l := range lines {
		lines[i] = "    " + l
	}
	return strings.Join(lines, "\n")
}

// queriesDir locates queries/ relative to this package. Go runs a test in its own
// package directory, so this is stable as long as the package does not move.
func queriesDir(t *testing.T) string {
	t.Helper()
	dir := filepath.Join("..", "..", "queries")
	if _, err := os.Stat(dir); err != nil {
		t.Fatalf("cannot find the queries directory at %s: %v", dir, err)
	}
	return dir
}
