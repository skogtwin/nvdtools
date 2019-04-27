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

package internal

import (
	"testing"
)

var (
	w = map[string]map[string]float64{
		"A": {
			"B": 0.5,
			"C": 0.2,
		},
	}
)

func testVector() Vector {
	v := NewVector(MapWeighter{w}, WeightsValidator{w})
	v.Set("A", "B")
	return v
}

func TestSet(t *testing.T) {
	v := testVector()
	if err := v.Set("A", "B"); err != nil {
		t.Errorf("should be able to set metric to valid value")
	}
	if err := v.Set("A", "D"); err == nil {
		t.Errorf("shouldn't be able to set metric to invalid value")
	}
}

func TestGet(t *testing.T) {
	v := testVector()
	if val, err := v.Get("A"); err != nil {
		t.Errorf("should be able to get value for set value")
	} else if val != "B" {
		t.Errorf("returned value should be the same as the one that was set")
	}
	if _, err := v.Get("B"); err == nil {
		t.Errorf("shouldn't be able to get value for metric that wasn't set")
	}
}

func TestEmpty(t *testing.T) {
	if !NewVector(nil, nil).Empty() {
		t.Errorf("empty vector should be empty")
	}
	if testVector().Empty() {
		t.Errorf("test vector shouldn't be empty")
	}
}

func TestWeight(t *testing.T) {
	v := testVector()
	if _, err := v.Weight("A"); err != nil {
		t.Errorf("should be able to get weight for metric A")
	}
	if _, err := v.Weight("B"); err == nil {
		t.Errorf("shouldn't be able to get weight for metric B")
	}
}

func TestWeightDefault(t *testing.T) {
	v := testVector()
	if w := v.WeightDefault("A", 42); w == 42 {
		t.Errorf("shouldn't use the default weight for metric A")
	}
	if w := v.WeightDefault("B", 42); w != 42 {
		t.Errorf("should use default weight for invalid metric A")
	}
}
