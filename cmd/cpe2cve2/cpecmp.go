package main

import (
	"flag"
	"fmt"
	"os"
	"strings"
)

var safeMatching = flag.Bool("-validate_cpes", false, "check the CPE is well-formed before trying to match it, ignore malformed ones; slower, but nerver panics.")

// CPEmatch returns true if a and b match character-by-character or at least one of those is ANY logical type ('*').
// For performance reasons, this function makes assumptions about a and b structure and may panic if those aren't valid WFNs serialized as formatted strings.
func CPEmatch(a, b string) bool {
	if *safeMatching {
		if !validCPE(a) || !validCPE(b) {
			fmt.Fprintf(os.Stderr, "invalid cpes: %s %s\n", a, b)
			return false
		}
	}

	a, b = a[8:], b[8:] // skip cpe:2.3: prefix
	for {
		// compare up to next separator...
		sa := strings.IndexByte(a, ':')
		sb := strings.IndexByte(b, ':')

		// ...or end of string, if it is the last part.
		// no need to check sb, well-formed CPE formatted string should have exactly 12 ':' no matter what
		if sa == -1 {
			return a == b
		}

		// none of the fields is ANY and they don't match
		if a[:sa] != b[:sb] && a[:sa] != "*" && b[:sa] != "*" {
			return false
		}

		// move to the next part of WFN
		a = a[sa+1:]
		b = b[sb+1:]
	}
}

func getCPEversion(cpe string) string {
	parts := strings.Split(cpe, ":")
	if len(parts) < 6 {
		return "*"
	}
	return parts[5]
}

func validCPE(cpe string) bool {
	if !strings.HasPrefix(cpe, "cpe:2.3:") || !hasAllParts(cpe) {
		return false
	}
	return true
}

func hasAllParts(cpe string) bool {
	n := 0
	for _, c := range cpe {
		if c == ':' {
			n++
		}
	}
	// cpe:2.3:o:microsoft:windows_xp:*:sp3:*:*:*:*:*:*
	return n == 12
}
