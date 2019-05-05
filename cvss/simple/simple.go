package simple

import (
	"fmt"
	"math"
	"strings"
)

var metricLevels = map[string]map[string]float64{
	"AV":                 {"N": 0.85, "A": 0.62, "L": 0.55, "P": 0.2},
	"AC":                 {"L": 0.77, "H": 0.44},
	"PR_scope_unchanged": {"N": 0.85, "L": 0.62, "H": 0.27},
	"PR_scope_changed":   {"N": 0.85, "L": 0.68, "H": 0.50},
	"UI":                 {"N": 0.85, "R": 0.62},
	"C":                  {"H": 0.56, "L": 0.22, "N": 0.0},
	"I":                  {"H": 0.56, "L": 0.22, "N": 0.0},
	"A":                  {"H": 0.56, "L": 0.22, "N": 0.0},
	"E":                  {"X": 1.0, "H": 1.0, "F": 0.97, "P": 0.94, "U": 0.91},
	"RL":                 {"X": 1.0, "U": 1.0, "W": 0.97, "T": 0.96, "O": 0.95},
	"RC":                 {"X": 1.0, "C": 1.0, "R": 0.96, "U": 0.92},
	"CR":                 {"X": 1.0, "H": 1.5, "M": 1.0, "L": 0.5},
	"IR":                 {"X": 1.0, "H": 1.5, "M": 1.0, "L": 0.5},
	"AR":                 {"X": 1.0, "H": 1.5, "M": 1.0, "L": 0.5},
}

var baseMetrics = []string{"AV", "AC", "PR", "UI", "S", "C", "I", "A"}
var temporalMetrics = []string{"E", "RL", "RC"}
var environmentalMetrics = []string{"CR", "IR", "AR"} // excluding Modified* ones

type Vector map[string]string

func FromVectorString(s string) (Vector, error) {
	v := make(Vector)
	v.addDefaults()
	// TODO: parse version from prefix, adjust return value accordingly
	if strings.HasPrefix(s, "CVSS:3.0/") {
		s = s[9:]
	}

	var readKey bool
	key := ""
	for readKey = true; s != ""; readKey = !readKey {
		if readKey {
			to := strings.Index(s, ":")
			if to == -1 {
				return nil, fmt.Errorf("bad metrics at %q", s)
			}
			key = s[:to]
			s = s[to+1:]
			continue
		}
		to := strings.Index(s, "/")
		if to == -1 {
			v[key] = s
			s = ""
		} else {
			v[key] = s[:to]
			s = s[to+1:]
		}
	}
	if err := v.Validate(); err != nil {
		return nil, fmt.Errorf("bad vector %q: %v", v, err)
	}
	return v, nil
}

func (vec Vector) Score(base bool) float64 {
	scopeChange := false

	if vec["S"] == "C" {
		scopeChange = true
	}
	if v, ok := vec["MS"]; ok && v != "X" {
		if v == "C" {
			scopeChange = true
		} else {
			scopeChange = false
		}
	}

	av := vec.maybeModifiedValue("AV", base)
	ac := vec.maybeModifiedValue("AC", base)
	ui := vec.maybeModifiedValue("UI", base)
	pr := vec.maybeModifiedPR(scopeChange, base) // weird...

	confi := vec.maybeModifiedValue(vec["C"], base)
	integ := vec.maybeModifiedValue(vec["I"], base)
	avail := vec.maybeModifiedValue(vec["A"], base)

	cr := metricLevels["CR"][vec["CR"]]
	ir := metricLevels["IR"][vec["IR"]]
	ar := metricLevels["AR"][vec["AR"]]

	e := metricLevels["E"][vec["E"]]
	rl := metricLevels["RL"][vec["RL"]]
	rc := metricLevels["RC"][vec["RC"]]

	// exploitability sub score
	ess := 0.82 * av * ac * pr * ui

	// impact sub score
	isc := 1.0 - math.Abs((1.0-confi*cr)*(1.0-integ*ir)*(1.0-avail*ar))
	// modified score should be ceiled to 0.915 for some reason that escapes me...
	if !base && isc > 0.915 {
		isc = 0.915
	}
	if scopeChange {
		isc = 7.52*math.Abs(isc-0.029) - 3.25*math.Pow(math.Abs(isc-0.02), 15.0)
	} else {
		isc *= 6.42
	}

	if isc < 0 {
		return 0.0
	}

	// actual score
	score := ess + isc
	if scopeChange {
		score *= 1.08
	}
	if score > 10.0 {
		score = 10.0
	}
	score = math.Ceil(score*10) / 10.0
	if base {
		return score
	}
	return math.Ceil(score*e*rl*rc*10) / 10.0

}

func (vec Vector) addDefaults() {
	for _, k := range temporalMetrics {
		if _, ok := vec[k]; !ok {
			vec[k] = "X"
		}
	}
	for _, k := range environmentalMetrics {
		if _, ok := vec[k]; !ok {
			vec[k] = "X"
		}
	}
}

func (vec Vector) Validate() error {
	// TODO: validate
	return nil
}

func (vec Vector) maybeModifiedValue(metric string, forceBase bool) float64 {
	altMetric := "M" + metric
	if !forceBase {
		if v, ok := vec[altMetric]; ok && v != "X" {
			return metricLevels[metric][v]
		}
	}
	return metricLevels[metric][vec[metric]]
}

func (vec Vector) maybeModifiedPR(scopeChange, forceBase bool) float64 {
	if !forceBase {
		if v, ok := vec["MPR"]; ok && v != "X" {
			if scopeChange {
				return metricLevels["PR_scope_changed"][v]
			}
			return metricLevels["PR_scope_unchanged"][v]
		}
	}
	if scopeChange {
		return metricLevels["PR_scope_changed"][vec["PR"]]
	}
	return metricLevels["PR_scope_unchanged"][vec["PR"]]
}
