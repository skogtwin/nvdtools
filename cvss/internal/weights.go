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
	"fmt"
)

// Weights holds weights for (metric, value) pairs
type Weights map[string]map[string]float64

// Weighter provides weights for (metric, value) pairs
type Weighter interface {
	// Weight returns weight for given metrics and metric
	// so for the maps below, it would return 0.85 for ({AV:N}, AV)
	Weight(metrics Metrics, metric string) (float64, error)
}

// impelments the weighter interface using a map
type MapWeighter struct {
	Weights
}

func (w MapWeighter) Weight(metrics Metrics, metric string) (float64, error) {
	value, ok := metrics[metric]
	if !ok {
		return 0, fmt.Errorf("value not defined for metric %s", metric)
	}
	m, ok := w.Weights[metric]
	if !ok {
		return 0, fmt.Errorf("metric %s not defined in weights", metric)
	}
	if weight, ok := m[value]; ok {
		return weight, nil
	}
	return 0, fmt.Errorf("value %s not defined for metric %s", value, metric)
}

type OverridenWeighter struct {
	Weighter
	ShouldOverride func() bool
	Overrides      Weights
}

func (w OverridenWeighter) Weight(metrics Metrics, metric string) (float64, error) {
	if w.ShouldOverride() {
		// try to override
		if values, ok := w.Overrides[metric]; ok { // there's an override for this metric
			if actualValue, ok := metrics[metric]; ok { // we have a value set for that metric
				if weight, ok := values[actualValue]; ok {
					return weight, nil
				}
			}
		}
	}
	return w.Weighter.Weight(metrics, metric)
}
