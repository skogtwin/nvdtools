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
	"strings"
)

// Metrics represents metrics set in some vector
type Metrics map[string]string

// Vector base interface for all vectors so we can make some functions generic
type Vector interface {
	// Set will set given metric to some value
	// returns an error if that value can't be set for that metric
	Set(metric, value string) error

	// Get gets the value in this vector for given metric
	// returns an error if there's no value stored
	Get(metric string) (string, error)

	// Empty returns whether this vector is emtpy
	Empty() bool

	// Weight gets the weight for given metric, used in formulas
	// returns an error if there's no value stored
	Weight(metric string) (float64, error)

	// WeightDefault does the same as Weight, but returns the default if error occurs
	WeightDefault(metric string, defaultWeight float64) float64
}

func NewVector(weighter Weighter, validator Validator) Vector {
	return vector{make(map[string]string), weighter, validator}
}

// underlying struct for other vectors
// it imlements some basic stuff, like storing and fetching of metrics
type vector struct {
	// this stores actual metrics values in this vector
	metrics Metrics

	// provides weights for metrics
	weighter Weighter

	// provides validation for metrics and values
	validator Validator
}

func (v vector) Set(metric, value string) error {
	if !v.validator.IsValueValidForMetric(metric, value) {
		return fmt.Errorf("value %s is not valid for %s", value, metric)
	}
	v.metrics[metric] = value
	return nil
}

func (v vector) Get(metric string) (string, error) {
	if !v.validator.IsMetricValid(metric) {
		return "", fmt.Errorf("metric %s is not valid for this vector", metric)
	}
	if value, ok := v.metrics[metric]; ok {
		return value, nil
	}
	return "", fmt.Errorf("vector doesn't have metric %s set", metric)
}

func (v vector) Empty() bool {
	return len(v.metrics) == 0
}

func (v vector) Weight(metric string) (float64, error) {
	return v.weighter.Weight(v.metrics, metric)
}

func (v vector) WeightDefault(metric string, defaultWeight float64) float64 {
	if w, err := v.Weight(metric); err == nil {
		return w
	}
	return defaultWeight
}

func (v vector) String() string {
	var parts []string
	for metric, value := range v.metrics {
		parts = append(parts, fmt.Sprintf("%s%s%s", metric, MetricSeparator, value))
	}
	return strings.Join(parts, PartSeparator)
}
