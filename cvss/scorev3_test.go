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

package cvss

import (
	"testing"
)

func TestSeverityFromScore(t *testing.T) {
	tests := map[float64]Severity{
		0.0:  SeverityNone,
		1.0:  SeverityLow,
		2.0:  SeverityLow,
		3.0:  SeverityLow,
		4.0:  SeverityMedium,
		5.0:  SeverityMedium,
		6.0:  SeverityMedium,
		7.0:  SeverityHigh,
		8.0:  SeverityHigh,
		9.0:  SeverityCritical,
		10.0: SeverityCritical,
	}

	for score, expected := range tests {
		if actual := SeverityFromScore(score); expected != actual {
			t.Errorf("score %.1f: expected %s, actual %s", score, expected, actual)
		}
	}
}

func TestRoundUp(t *testing.T) {
	tests := map[float64]float64{
		1.50:  1.5,
		1.51:  1.6,
		1.54:  1.6,
		1.55:  1.6,
		1.56:  1.6,
		1.59:  1.6,
		-1.50: -1.5,
		-1.51: -1.5,
		-1.54: -1.5,
		-1.55: -1.5,
		-1.56: -1.5,
		-1.59: -1.5,
	}

	for x, expected := range tests {
		if actual := roundUp(x); expected != actual {
			t.Errorf("x %.2f: expected %.1f, actual %.1f", x, expected, actual)
		}
	}
}

func TestScores(t *testing.T) {
	// random vector chosen and validated at:
	// https://www.first.org/cvss/calculator/3.0#CVSS:3.0/AV:P/AC:H/PR:H/UI:R/S:C/C:H/I:H/A:H/E:P/RL:T/RC:C/AR:L/MAV:P/MPR:H/MS:C/MC:H/MI:N/MA:H
	v := NewVectorV3()
	v.Parse("CVSS:3.0/AV:P/AC:H/PR:H/UI:R/S:C/C:H/I:H/A:H/E:P/RL:T/RC:C/AR:L/MAV:P/MPR:H/MS:C/MC:H/MI:N/MA:H")

	if s := v.BaseScore(); s != 6.8 {
		t.Errorf("base score expected to be %.1f, got %.1f", 6.8, s)
	}

	if s := v.TemporalScore(); s != 6.2 {
		t.Errorf("temporal score expected to be %.1f, got %.1f", 6.2, s)
	}

	if s := v.EnvironmentalScore(); s != 5.1 {
		t.Errorf("environmental score expected to be %.1f, got %.1f", 5.1, s)
	}
}
