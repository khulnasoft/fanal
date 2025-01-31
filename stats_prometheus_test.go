// SPDX-License-Identifier: MIT OR Apache-2.0

package main

import (
	"testing"

	"github.com/stretchr/testify/require"

	"github.com/khulnasoft/fanal/types"
)

func TestKhulnasoftNewCounterVec(t *testing.T) {
	c := &types.Configuration{
		Customfields: make(map[string]string),
	}
	c.Customfields["test"] = "foo"
	c.Customfields["should*fail"] = "bar"

	cv := getKhulnasoftNewCounterVec(c)
	shouldbe := []string{"hostname", "rule", "priority", "priority_raw", "source", "k8s_ns_name", "k8s_pod_name", "test"}
	mm, err := cv.GetMetricWithLabelValues(shouldbe...)
	if err != nil {
		t.Errorf("Error getting Metrics from promauto")
	}
	metricDescString := mm.Desc().String()
	require.Equal(t, metricDescString, "Desc{fqName: \"khulnasoft_fanal_khulnasoft_events_total\", help: \"\", constLabels: {}, variableLabels: {hostname,rule,priority,priority_raw,source,k8s_ns_name,k8s_pod_name,test}}")
}
