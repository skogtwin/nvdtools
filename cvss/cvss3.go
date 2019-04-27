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
	"fmt"

	. "github.com/facebookincubator/nvdtools/cvss/internal"
	. "github.com/facebookincubator/nvdtools/cvss/internalv3"
)

// VectorV3 represents a CVSSv3 vector
// It should only be created using NewVectorV3 function
type VectorV3 struct {
	baseVector          BaseVector
	temporalVector      TemporalVector
	environmentalVector EnvironmentalVector
}

func NewVectorV3() VectorV3 {
	v := VectorV3{}

	// crate base vector
	v.baseVector = BaseVector{
		NewVector(
			OverridenWeighter{
				Weighter: MapWeighter{
					Weights: BaseVectorWeights,
				},
				ShouldOverride: func() bool {
					// try to override only if the base scope has changed
					return v.baseScopeChanged()
				},
				Overrides: BaseVectorWeightsOverrides,
			},
			WeightsValidator{
				Weights: BaseVectorWeights,
			},
		),
	}

	// create temporal vector
	v.temporalVector = TemporalVector{
		NewVector(
			MapWeighter{
				Weights: TemporalVectorWeights,
			},
			WeightsValidator{
				Weights: TemporalVectorWeights,
			},
		),
	}

	// crate environmental vector
	v.environmentalVector = EnvironmentalVector{
		NewVector(
			OverridenWeighter{
				Weighter: MapWeighter{
					Weights: EnvironmentalVectorWeights,
				},
				ShouldOverride: func() bool {
					// try to override only if the base scope has changed
					return v.baseScopeChanged()
				},
				Overrides: EnvironmentalVectorWeightsOverrides,
			},
			WeightsValidator{
				Weights: EnvironmentalVectorWeights,
			},
		),
	}

	return v
}

func (v VectorV3) Validate() error {
	// base vector is valid only if it has all metrics defined
	for metric := range BaseVectorWeights {
		if _, err := v.baseVector.Get(metric); err != nil {
			return fmt.Errorf("base vector: metric %s not defined", metric)
		}
	}
	return nil
}

func (v VectorV3) Get(metric string) (string, error) {
	if value, err := v.baseVector.Get(metric); err == nil {
		return value, nil
	}
	if value, err := v.temporalVector.Get(metric); err == nil {
		return value, nil
	}
	if value, err := v.environmentalVector.Get(metric); err == nil {
		return value, nil
	}
	return "", fmt.Errorf("metric %s not defined/set for vector", metric)
}

func (v VectorV3) Set(metric, value string) error {
	if err := v.baseVector.Set(metric, value); err == nil {
		return nil
	}
	if err := v.temporalVector.Set(metric, value); err == nil {
		return nil
	}
	if err := v.environmentalVector.Set(metric, value); err == nil {
		return nil
	}
	return fmt.Errorf("metric %s and value %s not defined for vector", metric, value)
}

// helper functions

func (v VectorV3) baseWeight(metric string) float64 {
	// all base metric must be defined
	w, err := v.baseVector.Weight(metric)
	if err != nil {
		panic(err) // won't happen because of validate
	}
	return w
}

func (v VectorV3) modifiedWeight(metric string) float64 {
	// get M${metric} from environmental vector
	// if it's not defined, then get the same for $metric from the base vector
	if w, err := v.environmentalVector.Weight("M" + metric); err == nil {
		return w
	}

	return v.baseWeight(metric)
}

func (v VectorV3) baseScopeChanged() bool {
	// base scope must be defined
	if scope, err := v.Get("S"); err == nil {
		return scope == "C"
	}
	panic("scope not defined in base vector") // won't happen because of validate
}

func (v VectorV3) modifiedScopeChanged() bool {
	// try to get modified scope first
	// if it's not defined then get the base scope
	if scope, err := v.environmentalVector.Get("MS"); err == nil {
		return scope == "C"
	}
	return v.baseScopeChanged()
}
