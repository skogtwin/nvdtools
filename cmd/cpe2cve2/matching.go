package main

import (
	"strings"
)

type operator func(before, now bool) (result, stop bool)

func or(before, now bool) (result, stop bool) {
	if before || now {
		return true, true
	}
	return false, false
}

func and(before, now bool) (result, stop bool) {
	if !(before && now) {
		return false, true
	}
	return true, false
}

func matchMatch(ret []string, match *Match, cpes ...string) ([]string, bool) {
	matched := false
	cpeURI := match.Cpe23Uri
	for _, cpe := range cpes {
		result := CPEmatch(cpeURI, cpe)
		if !result {
			continue
		}

		version := getCPEversion(cpe)
		if version == "*" {
			ret = append(ret, cpe)
			matched = true
			continue
		}

		if match.VersionStartIncluding != "" {
			if smartVerCmp(version, match.VersionStartIncluding) < 0 {
				continue
			}
		}
		if match.VersionStartExcluding != "" {
			if smartVerCmp(version, match.VersionStartExcluding) != 1 {
				continue
			}
		}
		if match.VersionEndIncluding != "" {
			if smartVerCmp(version, match.VersionEndIncluding) > 0 {
				continue
			}
		}
		if match.VersionEndExcluding != "" {
			if smartVerCmp(version, match.VersionEndExcluding) != -1 {
				continue
			}
		}
		ret = append(ret, cpe)
		matched = true
	}
	return ret, matched
}

func matchNode(matches []string, node *Node, cpes ...string) ([]string, bool) {
	var (
		result         bool
		hasMatch, stop bool
		op             operator
	)

	switch node.Operator {
	case "OR":
		op = or
	case "AND":
		op = and
	default:
		panic("unknown operator: " + node.Operator)
	}

	for i, n := range node.Children {
		matches, hasMatch = matchNode(matches, n, cpes...)
		if i == 0 {
			result, stop = hasMatch, false
		} else {
			result, stop = op(result, hasMatch)
		}
		if stop {
			break
		}
	}
	// The node will either have Children or CPEMatch, not both
	if result {
		return matches, result
	}

	for i, match := range node.CPEMatch {
		matches, hasMatch = matchMatch(matches, match, cpes...)
		if i == 0 {
			result, stop = hasMatch, false
		} else {
			result, stop = op(result, hasMatch)
		}
		if stop {
			break
		}
	}
	return matches, result
}

func MatchCVE(cve *CVE, cpes ...string) []string {
	var (
		ret      []string
		hasMatch bool
	)
	for _, node := range cve.Nodes() {
		if ret, hasMatch = matchNode(ret, node, cpes...); hasMatch {
			break
		}
	}
	return ret
}

// smartVerCmp compares stringified versions of software.
// It tries to do the right thing for any type of versioning,
// assuming v1 and v2 have the same version convension.
// It will return meaningful result for "95SE" vs "98SP1" or for "16.3.2" vs. "3.7.0",
// but not for "2000" vs "11.7".
// Returns -1 if v1 < v2, 1 if v1 > v2 and 0 if v1 == v2.
func smartVerCmp(v1, v2 string) int {
	for s1, s2 := v1, v2; len(s1) > 0 && len(s2) > 0; {
		num1, cmpTo1, skip1 := parseVerParts(s1)
		num2, cmpTo2, skip2 := parseVerParts(s2)

		ns1 := s1[:cmpTo1]
		ns2 := s2[:cmpTo2]
		diff := num1 - num2
		switch {
		case diff > 0: // ns1 has longer numeric part
			ns2 = lpad(ns2, diff)
		case diff < 0: // ns2 has longer numeric part
			ns1 = lpad(ns1, -diff)
		}

		if cmp := strings.Compare(ns1, ns2); cmp != 0 {
			return cmp
		}

		s1 = s1[skip1:]
		s2 = s2[skip2:]
	}
	// everything is equal so far, the longest wins
	if len(v1) > len(v2) {
		return 1
	}
	if len(v2) > len(v1) {
		return -1
	}
	return 0
}

// parseVerParts returns the length of consecutive run of digits in the beginning of the string,
// the last non-separator chararcted (which should be compared), and index at which the version part (major, minor etc.) ends,
// i.e. the position of the dot or end of the line.
// E.g. parseVerParts("11b.4.16-New_Year_Edition") will return (2, 3, 4)
func parseVerParts(v string) (int, int, int) {
	var num int
	for num = 0; num < len(v); num++ {
		if v[num] < '0' || v[num] > '9' {
			break
		}
	}
	if num == len(v) {
		return num, num, num
	}
	// Any punctuation separates the parts.
	skip := strings.IndexFunc(v, func(b rune) bool {
		// !"#$%&'()*+,-./ are dec 33 to 47, :;<=>?@ are dec 58 to 64, [\]^_` are dec 91 to 96 and {|}~ are dec 123 to 126.
		// So, punctuation is in dec 33-126 range except 48-57, 65-90 and 97-122 gaps.
		// This inverse logic allows for early short-circuting for most of the chars and shaves ~20ns in benchmarks.
		return b >= '!' && b <= '~' &&
			!(b > '/' && b < ':' ||
				b > '@' && b < '[' ||
				b > '`' && b < '{')
	})
	if skip == -1 {
		return num, len(v), len(v)
	}
	return num, skip, skip + 1
}

// lpad pads s with n '0's
func lpad(s string, n int) string {
	var sb strings.Builder
	for i := 0; i < n; i++ {
		sb.WriteByte('0')
	}
	sb.WriteString(s)
	return sb.String()
}
