package main

import (
	"strings"
	"testing"
)

// The help used to advertise ten nouns and about thirty-seven verbs that did not exist,
// each answering "not implemented yet" when anybody took it up. Generating the text from
// the dispatch table makes that unexpressible; this checks the generation rather than
// trusting it, because the cheap way to reintroduce the problem is a hand-written line.
func TestEveryCommandOfferedCanBeRun(t *testing.T) {
	text := usageText()

	body, ok := strings.CutPrefix(text[strings.Index(text, "Commands:"):], "Commands:\n")
	if !ok {
		t.Fatal("the help has no Commands section")
	}
	body, _, _ = strings.Cut(body, "\nFlags:")

	offered := 0
	for _, line := range strings.Split(strings.TrimSpace(body), "\n") {
		name, _, _ := strings.Cut(strings.TrimSpace(line), " ")
		if name == "" {
			continue
		}
		offered++
		cmd, found := lookup(name)
		if !found {
			t.Errorf("the help offers %q and nothing dispatches it", name)
			continue
		}
		if cmd.run == nil {
			t.Errorf("%q is dispatched to nothing", name)
		}
	}
	if offered != len(commands) {
		t.Errorf("the help lists %d commands, the table holds %d", offered, len(commands))
	}
}

// The other direction: something that exists but is not offered is a command nobody can
// find, which is the same failure wearing the opposite hat.
func TestEveryCommandThatExistsIsOffered(t *testing.T) {
	text := usageText()
	for _, c := range commands {
		if !strings.Contains(text, "  "+c.name) {
			t.Errorf("%q is dispatched and the help does not mention it", c.name)
		}
		if c.help == "" {
			t.Errorf("%q is offered with no description", c.name)
		}
	}
}

// ADR-0032 §4: a verb appears when it works, and until then the answer is that there is no
// such command — which is true — rather than an apology for an offer that should not have
// been made.
func TestTheNounsThatWereNeverBuiltAreNotCommands(t *testing.T) {
	for _, name := range []string{
		"device", "network", "user", "group", "acl",
		"dns", "route-group", "exit", "relay", "token",
	} {
		if _, found := lookup(name); found {
			t.Errorf("%q resolves; if it is implemented it belongs in the help", name)
		}
		// The command column, not the whole text. "device" appears in the description of
		// `join`, which is prose about what the command does rather than an offer to run
		// something called device.
		if offers(usageText(), name) {
			t.Errorf("the help offers %q as a command", name)
		}
	}
}

// offers reports whether the help lists name in its command column.
func offers(text, name string) bool {
	body := text[strings.Index(text, "Commands:"):]
	body, _, _ = strings.Cut(body, "\nFlags:")
	for _, line := range strings.Split(body, "\n") {
		first, _, _ := strings.Cut(strings.TrimSpace(line), " ")
		if first == name {
			return true
		}
	}
	return false
}
