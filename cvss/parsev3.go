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
	"strings"

	"github.com/facebookincubator/nvdtools/cvss/internal"

	"github.com/pkg/errors"
)

const (
	prefix = "CVSS:3.0/"
)

func (v VectorV3) Parse(str string) error {
	// remove prefix if exists
	if strings.HasPrefix(str, prefix) {
		str = str[len(prefix):]
	} else if strings.HasPrefix(str, strings.ToLower(prefix)) {
		str = str[len(prefix):]
	}

	metrics, err := strToMetrics(str)
	if err != nil {
		return errors.Wrapf(err, "can't parse vector to metrics")
	}

	for metric, value := range metrics {
		if err := v.Set(metric, value); err != nil {
			return fmt.Errorf("can't set metric %s to %s", metric, value)
		}
	}

	return nil
}

func (v VectorV3) String() string {
	var sb strings.Builder
	fmt.Fprintf(&sb, "%s%s", prefix, v.baseVector)
	if !v.temporalVector.Empty() {
		fmt.Fprintf(&sb, "%s%s", internal.PartSeparator, v.temporalVector)
	}
	if !v.environmentalVector.Empty() {
		fmt.Fprintf(&sb, "%s%s", internal.PartSeparator, v.environmentalVector)
	}
	return sb.String()
}

// parse A:B/C:D into map{A:B, C:D}
func strToMetrics(str string) (map[string]string, error) {
	metrics := make(map[string]string)
	for _, part := range strings.Split(str, internal.PartSeparator) {
		tmp := strings.Split(part, internal.MetricSeparator)
		if len(tmp) != 2 {
			return nil, fmt.Errorf("need two values separated by %s, got %q", internal.MetricSeparator, part)
		}
		metric, value := tmp[0], tmp[1]
		if _, exists := metrics[metric]; exists {
			return nil, fmt.Errorf("metric %s already set", metric)
		}
		metrics[metric] = value
	}
	return metrics, nil
}
