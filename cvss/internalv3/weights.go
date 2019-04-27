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

package internalv3

var (
	BaseVectorWeights = map[string]map[string]float64{
		"AV": { // Attack Vector
			"N": 0.85, // Network
			"A": 0.62, // Adjecent
			"L": 0.55, // Local
			"P": 0.20, // Physical
		},
		"AC": { // Attack Complexity
			"L": 0.77, // Low
			"H": 0.44, // High
		},
		"PR": { // Privileges Required
			"N": 0.85, // None
			"L": 0.62, // Low; 0.68 if Scope changed
			"H": 0.27, // High; 0.50 if Scope changed
		},
		"UI": { // User Interaction
			"N": 0.85, // None
			"R": 0.62, // Required
		},
		"S": { // Scope; no values, but need the keys
			"U": 0.0, // Unchanged
			"C": 0.0, // Changed
		},
		"C": { // Confidentiality
			"H": 0.56, // High
			"L": 0.22, // Low
			"N": 0.00, // None
		},
		"I": {
			"H": 0.56, // High
			"L": 0.22, // Low
			"N": 0.00, // None
		},
		"A": {
			"H": 0.56, // High
			"L": 0.22, // Low
			"N": 0.00, // None
		},
	}

	// overrides for when base scope is changed
	BaseVectorWeightsOverrides = map[string]map[string]float64{
		"PR": { // Privileges Required
			"L": 0.68, // Low
			"H": 0.50, // High
		},
	}

	TemporalVectorWeights = map[string]map[string]float64{
		"E": { // Exploit Code Maturity
			"H": 1.00, // High
			"F": 0.97, // Functional
			"P": 0.94, // Proof-Of-Concept
			"U": 0.91, // Unproven
		},
		"RL": { // Remediation Level
			"U": 1.00, // Unavailable
			"W": 0.97, // Workaround
			"T": 0.96, // Temporary Fix
			"O": 0.95, // Official Fix
		},
		"RC": { // Report Confidence
			"C": 1.00, // Confirmed
			"R": 0.96, // Reasonable
			"U": 0.92, // Unknown
		},
	}

	EnvironmentalVectorWeights = map[string]map[string]float64{
		"CR": { // Confidentiality Requirement
			"H": 1.50, // High
			"M": 1.00, // Medium
			"L": 0.50, // Low
		},
		"IR": { // Integrity Requirement
			"H": 1.50, // High
			"M": 1.00, // Medium
			"L": 0.50, // Low
		},
		"AR": { // Availability Requirement
			"H": 1.50, // High
			"M": 1.00, // Medium
			"L": 0.50, // Low
		},
		// + the ones from base vector, see init function below
	}

	// overrides for when modified scope is changed
	EnvironmentalVectorWeightsOverrides = map[string]map[string]float64{
		"MPR": { // Privileges Required
			"L": 0.68, // Low
			"H": 0.50, // High
		},
	}
)

func init() {
	for metric, values := range BaseVectorWeights {
		EnvironmentalVectorWeights["M"+metric] = values
	}
}
