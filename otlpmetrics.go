package main

import (
	"fmt"
	"regexp"
	"strings"

	"github.com/khulnasoft/fanal/internal/pkg/utils"
	"github.com/khulnasoft/fanal/outputs/otlpmetrics"
	"github.com/khulnasoft/fanal/types"
)

func newOTLPMetrics(config *types.Configuration) *otlpmetrics.OTLPMetrics {
	otlpMetrics = &otlpmetrics.OTLPMetrics{
		Khulnasoft: newOTLPKhulnasoftMatchesCounter(config),
		Inputs:     newOTLPInputsCounter(),
		Outputs:    newOTLPOutputsCounter(),
	}
	return otlpMetrics
}

func newOTLPInputsCounter() otlpmetrics.Counter {
	supportedAttributes := []string{"source", "status"}
	name := "fanal_inputs"
	description := "Number of times an input is received"
	counter := otlpmetrics.NewCounter(name, description, supportedAttributes)
	return counter
}

func newOTLPOutputsCounter() otlpmetrics.Counter {
	name := "fanal_outputs"
	description := "Number of times an output is generated"
	supportedAttributes := []string{"destination", "status"}
	counter := otlpmetrics.NewCounter(name, description, supportedAttributes)
	return counter
}

func newOTLPKhulnasoftMatchesCounter(config *types.Configuration) otlpmetrics.Counter {
	regOTLPLabels, _ := regexp.Compile("^[a-zA-Z_:][a-zA-Z0-9_:]*$")

	supportedAttributes := []string{
		"source",
		"priority",
		"rule",
		"hostname",
		"tags",
		"k8s_ns_name",
		"k8s_pod_name",
	}
	for i := range config.Customfields {
		if !regOTLPLabels.MatchString(i) {
			utils.Log(utils.ErrorLvl, "", fmt.Sprintf("Custom field '%v' is not a valid OTLP metric attribute name", i))
			continue
		}
		supportedAttributes = append(supportedAttributes, i)
	}

	for _, i := range config.OTLP.Metrics.ExtraAttributesList {
		if !regOTLPLabels.MatchString(strings.ReplaceAll(i, ".", "_")) {
			utils.Log(utils.ErrorLvl, "", fmt.Sprintf("Extra field '%v' is not a valid OTLP metric attribute name", i))
			continue
		}
		supportedAttributes = append(supportedAttributes, strings.ReplaceAll(i, ".", "_"))
	}

	name := "khulnasoft_khulnasoft_rules_matches_total"
	description := "Number of times rules match"
	counter := otlpmetrics.NewCounter(name, description, supportedAttributes)
	return counter
}
