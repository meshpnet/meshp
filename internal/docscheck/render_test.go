package docscheck

import (
	"fmt"
	"testing"
)

// Not a check — a way to see the table this derives, so somebody fixing a document can copy
// what it should say rather than working it out. Run with -v.
func TestPrintTheTable(t *testing.T) {
	table, err := Table("../..")
	if err != nil {
		t.Fatal(err)
	}
	fmt.Println(table)
}
