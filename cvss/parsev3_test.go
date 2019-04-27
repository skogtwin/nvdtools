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
	"reflect"
	"testing"
)

func TestStrToMetrics(t *testing.T) {
	str := "A:B/C:D"
	expected := map[string]string{"A": "B", "C": "D"}
	if m, err := strToMetrics(str); err != nil {
		t.Errorf("should be able to parse A:B/C:D")
	} else if !reflect.DeepEqual(m, expected) {
		t.Errorf("parsed %s incorrectly, expecting %q, got %q", str, expected, m)
	}

	str = "A:B/C"
	if _, err := strToMetrics(str); err == nil {
		t.Errorf("shouldn't be able to parse %q", str)
	}

	str = "A:B/A:C"
	if _, err := strToMetrics(str); err == nil {
		t.Errorf("should fail when provided multiple values for the same metric")
	}
}

func TestParse(t *testing.T) {
	// all possible metrics are defined in these 3 strings
	base := "AV:P/AC:H/PR:L/UI:R/S:C/C:L/I:L/A:L"
	temporal := "E:U/RL:T/RC:R"
	environmental := "CR:H/IR:M/AR:L/MAV:P/MAC:H/MPR:L/MUI:R/MS:U/MC:L/MI:L/MA:H"

	v := NewVectorV3()
	if err := v.Parse(base); err != nil {
		t.Fatal(err)
	}
	if err := v.Parse(temporal); err != nil {
		t.Fatal(err)
	}
	if err := v.Parse(environmental); err != nil {
		t.Fatal(err)
	}

	tests := map[string]string{
		// base vector
		"AV": "P",
		"AC": "H",
		"PR": "L",
		"UI": "R",
		"S":  "C",
		"C":  "L",
		"I":  "L",
		"A":  "L",
		// temporal vector
		"E":  "U",
		"RL": "T",
		"RC": "R",
		// environmental vector
		"CR":  "H",
		"IR":  "M",
		"AR":  "L",
		"MAV": "P",
		"MAC": "H",
		"MPR": "L",
		"MUI": "R",
		"MS":  "U",
		"MC":  "L",
		"MI":  "L",
		"MA":  "H",
	}

	for metric, value := range tests {
		if val, err := v.Get(metric); err != nil {
			t.Fatal(err)
		} else if val != value {
			t.Errorf("expecting %s, got %s", value, val)
		}
	}
}
