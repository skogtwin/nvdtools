// Copyright (c) Facebook, Inc. and its affiliates.
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//     http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

// scoring is implemented based on the specification at:
// https://www.first.org/cvss/specification-document

package cvss

import (
	"math"
)

// Severity represents scores severity
type Severity int

const (
	SeverityNone Severity = iota
	SeverityLow
	SeverityMedium
	SeverityHigh
	SeverityCritical
)

func (s Severity) String() string {
	switch s {
	case SeverityNone:
		return "None"
	case SeverityLow:
		return "Low"
	case SeverityMedium:
		return "Medium"
	case SeverityHigh:
		return "High"
	case SeverityCritical:
		return "Critical"
	default:
		panic("undefined severity")
	}
}

// SeverityFromScore will return the severity assigned to given score
func SeverityFromScore(score float64) Severity {
	if score <= 0 {
		return SeverityNone
	}
	if 0 < score && score < 4 {
		return SeverityLow
	}
	if 4 <= score && score < 7 {
		return SeverityMedium
	}
	if 7 <= score && score < 9 {
		return SeverityHigh
	}
	return SeverityCritical
}

const (
	exploitabilityCoefficient = 8.22
	scopeCoefficient          = 1.08
)

func roundUp(x float64) float64 {
	// round up to one decimal
	return math.Ceil(x*10) / 10
}

// Score = combined score for the whole vector
func (v VectorV3) Score() float64 {
	// combines all of them
	return v.EnvironmentalScore()
}

// BaseScore returns the base score
func (v VectorV3) BaseScore() float64 {
	i, e := v.ImpactScore(), v.ExploitabilityScore()
	if i < 0 {
		return 0
	}
	c := 1.0
	if v.baseScopeChanged() {
		c = scopeCoefficient
	}

	return roundUp(math.Min(c*(e+i), 10.0))
}

// ImpactScore returns the impact sub score of the base score
func (v VectorV3) ImpactScore() float64 {
	iscBase := 1 - (1-v.baseWeight("C"))*(1-v.baseWeight("I"))*(1-v.baseWeight("A"))
	if v.baseScopeChanged() {
		return 7.52*(iscBase-0.029) - 3.25*math.Pow((iscBase-0.02), 15)
	} else {
		return 6.42 * iscBase
	}
}

// ExploitablityScore returns the exploitability sub score of the base score
func (v VectorV3) ExploitabilityScore() float64 {
	return exploitabilityCoefficient * v.baseWeight("AV") * v.baseWeight("AC") * v.baseWeight("PR") * v.baseWeight("UI")
}

// TemporalScore returns the temporal score
func (v VectorV3) TemporalScore() float64 {
	tv := v.temporalVector
	return roundUp(v.BaseScore() * tv.WeightDefault("E", 1.0) * tv.WeightDefault("RL", 1.0) * tv.WeightDefault("RC", 1.0))
}

// EnvironmentalScore return the environmental score
func (v VectorV3) EnvironmentalScore() float64 {
	i, e := v.ModifiedImpactScore(), v.ModifiedExploitabilityScore()
	if i < 0 {
		return 0
	}
	c := 1.0
	if v.modifiedScopeChanged() {
		c = scopeCoefficient
	}

	tv := v.temporalVector
	return roundUp(roundUp(math.Min(c*(e+i), 10.0)) * tv.WeightDefault("E", 1.0) * tv.WeightDefault("RL", 1.0) * tv.WeightDefault("RC", 1.0))
}

// ModifedImpactScore returns the impact sub score of the environmental score
func (v VectorV3) ModifiedImpactScore() float64 {
	ev := v.environmentalVector
	iscModified := math.Min(
		1-(1-v.modifiedWeight("C")*ev.WeightDefault("CR", 1.0))*
			(1-v.modifiedWeight("I")*ev.WeightDefault("IR", 1.0))*
			(1-v.modifiedWeight("A")*ev.WeightDefault("AR", 1.0)),
		0.915,
	)
	if v.modifiedScopeChanged() {
		return 7.52*(iscModified-0.029) - 3.25*math.Pow((iscModified-0.02), 15)
	} else {
		return 6.42 * iscModified
	}
}

// ModifiedExplotiabilityScore returns the explotiablity sub score of the environmental score
func (v VectorV3) ModifiedExploitabilityScore() float64 {
	return exploitabilityCoefficient * v.modifiedWeight("AV") * v.modifiedWeight("AC") * v.modifiedWeight("PR") * v.modifiedWeight("UI")
}
