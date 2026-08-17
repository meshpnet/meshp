package nftables

import (
	"encoding/json"
	"fmt"
	"sort"
	"strings"
)

// Refusal names something on this host that will drop packets meshp means to carry.
//
// A description rather than a handle, because meshp does not act on it. The operator is the
// one who can decide whether the other tool's rule or meshp's forwarding is the one that
// should give way, and they need to be told which tool to go and look at.
type Refusal struct {
	Family string // ip, ip6, inet
	Table  string
	Chain  string
}

func (r Refusal) String() string { return r.Family + " " + r.Table + " " + r.Chain }

// forwardRefusals finds base chains at the forward hook that drop by default.
//
// Why this can happen at all is worth stating, because the ruleset meshp writes looks
// correct while it does. Every base chain registered at a hook runs, in priority order, and
// a drop in any of them ends the packet. An accept only means *that* chain is finished with
// it. So meshp's forward chain accepting a carried prefix does not survive another table
// dropping it afterwards, and there is no rule meshp can write in its own table to win.
//
// Docker sets exactly this policy on every host it is installed on, and so do firewalld and
// several VPN clients. The result is an advertiser that renders a correct ruleset, reports
// the route group applied, and carries nothing.
//
// A drop policy is a strong signal rather than a proof: the other chain may hold a rule that
// accepts this traffic before the policy is reached, and deciding that would mean evaluating
// somebody else's ruleset against a hypothetical packet. So this reports what it found and
// says it plainly, rather than claiming forwarding is definitely broken.
//
// meshp's own tables are excluded. The forward chain here is policy accept today, but a
// device reporting itself as refusing its own traffic would be a confusing way to find out
// that had changed.
func forwardRefusals(chainsJSON []byte) ([]Refusal, error) {
	var doc struct {
		Nftables []struct {
			Chain *struct {
				Family string `json:"family"`
				Table  string `json:"table"`
				Name   string `json:"name"`
				Hook   string `json:"hook"`
				Policy string `json:"policy"`
			} `json:"chain"`
		} `json:"nftables"`
	}
	if err := json.Unmarshal(chainsJSON, &doc); err != nil {
		return nil, fmt.Errorf("nftables: reading the chain list: %w", err)
	}

	var out []Refusal
	for _, entry := range doc.Nftables {
		c := entry.Chain
		if c == nil {
			continue
		}
		// Only base chains are registered at a hook, and only they have a policy. A
		// regular chain is reached by a jump and cannot drop anything on its own.
		if c.Hook != "forward" || strings.ToLower(c.Policy) != "drop" {
			continue
		}
		if isOurTable(c.Table) {
			continue
		}
		out = append(out, Refusal{Family: c.Family, Table: c.Table, Chain: c.Name})
	}

	// Sorted so the same host reports the same thing every pass, rather than reordering
	// with whatever nft happened to list first and looking like a new condition.
	sort.Slice(out, func(i, j int) bool { return out[i].String() < out[j].String() })
	return out, nil
}

// isOurTable reports whether a table is one meshp writes.
func isOurTable(name string) bool {
	switch name {
	case TableName, ForwardTableName, LockTableName, MapTableName:
		return true
	}
	// The mapping tests install per-interface variants, and a device that somehow held one
	// should not report itself as its own obstacle.
	return strings.HasPrefix(name, MapTableName+"_")
}
