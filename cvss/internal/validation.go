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

// Validator validates metrics and values
type Validator interface {
	IsMetricValid(metric string) bool
	IsValueValidForMetric(metric, value string) bool
}

// simple validator which uses weights map to check validity
type WeightsValidator struct {
	Weights
}

func (v WeightsValidator) IsMetricValid(metric string) bool {
	_, ok := v.Weights[metric]
	return ok
}

func (v WeightsValidator) IsValueValidForMetric(metric, value string) bool {
	if !v.IsMetricValid(metric) {
		return false
	}
	_, ok := v.Weights[metric][value]
	return ok
}
