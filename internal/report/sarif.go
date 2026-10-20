package report

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strings"

	"github.com/omni-line/mal-check/internal/scan"
)

// SARIF 2.1.0 output for GitHub code scanning and other SAST dashboards.
// Only the subset of the schema that mal-check populates is modeled.

const (
	sarifSchema          = "https://json.schemastore.org/sarif-2.1.0.json"
	sarifRuleMalicious   = "MC001"
	sarifRuleCompromised = "MC002"
	toolInfoURI          = "https://github.com/omni-line/mal-check"
	fingerprintK         = "malCheck/v1"
)

type sarifLog struct {
	Schema  string     `json:"$schema"`
	Version string     `json:"version"`
	Runs    []sarifRun `json:"runs"`
}

type sarifRun struct {
	Tool        sarifTool         `json:"tool"`
	Invocations []sarifInvocation `json:"invocations"`
	Results     []sarifResult     `json:"results"`
}

type sarifTool struct {
	Driver sarifDriver `json:"driver"`
}

type sarifDriver struct {
	Name           string      `json:"name"`
	Version        string      `json:"version,omitempty"`
	InformationURI string      `json:"informationUri"`
	Rules          []sarifRule `json:"rules"`
}

type sarifRule struct {
	ID                   string          `json:"id"`
	Name                 string          `json:"name"`
	ShortDescription     sarifText       `json:"shortDescription"`
	FullDescription      sarifText       `json:"fullDescription"`
	Help                 sarifText       `json:"help"`
	HelpURI              string          `json:"helpUri"`
	DefaultConfiguration sarifRuleConfig `json:"defaultConfiguration"`
	Properties           map[string]any  `json:"properties,omitempty"`
}

type sarifRuleConfig struct {
	Level string `json:"level"`
}

type sarifText struct {
	Text string `json:"text"`
}

type sarifInvocation struct {
	ExecutionSuccessful        bool                `json:"executionSuccessful"`
	ToolExecutionNotifications []sarifNotification `json:"toolExecutionNotifications,omitempty"`
}

type sarifNotification struct {
	Level   string    `json:"level"`
	Message sarifText `json:"message"`
}

type sarifResult struct {
	RuleID              string            `json:"ruleId"`
	Level               string            `json:"level"`
	Message             sarifText         `json:"message"`
	Locations           []sarifLocation   `json:"locations"`
	PartialFingerprints map[string]string `json:"partialFingerprints"`
	Properties          map[string]string `json:"properties,omitempty"`
}

type sarifLocation struct {
	PhysicalLocation sarifPhysical `json:"physicalLocation"`
}

type sarifPhysical struct {
	ArtifactLocation sarifArtifact `json:"artifactLocation"`
	Region           *sarifRegion  `json:"region,omitempty"`
}

type sarifArtifact struct {
	URI string `json:"uri"`
}

type sarifRegion struct {
	StartLine int `json:"startLine"`
}

func writeSARIF(w io.Writer, res *scan.Result, opts Options) error {
	log := sarifLog{
		Schema:  sarifSchema,
		Version: "2.1.0",
		Runs: []sarifRun{{
			Tool: sarifTool{Driver: sarifDriver{
				Name:           "mal-check",
				Version:        strings.TrimPrefix(opts.Version, "v"),
				InformationURI: toolInfoURI,
				Rules:          []sarifRule{maliciousRule(), compromisedRule()},
			}},
			Invocations: []sarifInvocation{invocation(res)},
			Results:     make([]sarifResult, 0, len(res.Findings)),
		}},
	}
	shown, _ := visible(res.Findings, opts.MinSeverity)
	for _, f := range shown {
		log.Runs[0].Results = append(log.Runs[0].Results, sarifFinding(f))
	}
	enc := json.NewEncoder(w)
	enc.SetIndent("", "  ")
	if err := enc.Encode(log); err != nil {
		return fmt.Errorf("encode sarif: %w", err)
	}
	return nil
}

func maliciousRule() sarifRule {
	return sarifRule{
		ID:   sarifRuleMalicious,
		Name: "KnownMaliciousPackage",
		ShortDescription: sarifText{
			Text: "Dependency was published to a public registry as malware",
		},
		FullDescription: sarifText{
			Text: "The dependency matches an OpenSSF malicious-packages (MAL-) advisory for this " +
				"name, at this version or at every version. Malicious packages typically run " +
				"their payload in install scripts, so any machine that installed it may be compromised.",
		},
		Help: sarifText{
			Text: scan.Remediation,
		},
		HelpURI:              toolInfoURI + "#readme",
		DefaultConfiguration: sarifRuleConfig{Level: "error"},
		Properties: map[string]any{
			"tags":              []string{"security", "supply-chain", "malware"},
			"security-severity": "9.8",
			"precision":         "very-high",
		},
	}
}

func compromisedRule() sarifRule {
	return sarifRule{
		ID:   sarifRuleCompromised,
		Name: "PreviouslyCompromisedPackage",
		ShortDescription: sarifText{
			Text: "Dependency shipped malicious releases in the past",
		},
		FullDescription: sarifText{
			Text: "Specific versions of this dependency were published as malware (for example " +
				"after a maintainer account takeover). The locked version is not one of them.",
		},
		Help: sarifText{
			Text: scan.RemediationCompromised,
		},
		HelpURI:              toolInfoURI + "#readme",
		DefaultConfiguration: sarifRuleConfig{Level: "note"},
		Properties: map[string]any{
			"tags":              []string{"security", "supply-chain", "malware"},
			"security-severity": "3.1",
			"precision":         "high",
		},
	}
}

func invocation(res *scan.Result) sarifInvocation {
	inv := sarifInvocation{ExecutionSuccessful: res.Complete()}
	for _, wn := range res.Warnings {
		inv.ToolExecutionNotifications = append(inv.ToolExecutionNotifications, sarifNotification{
			Level:   "warning",
			Message: sarifText{Text: fmt.Sprintf("%s: %s", wn.Manifest, wn.Message)},
		})
	}
	return inv
}

func sarifFinding(f scan.Finding) sarifResult {
	uri := sarifURI(f.Manifest)
	ruleID := sarifRuleMalicious
	ids := strings.Join(f.IDs, ", ")
	msg := fmt.Sprintf("%s package %q is a known malicious package (%s).", f.Ecosystem, f.Package, ids)
	switch {
	case f.Reason == scan.ReasonCompromised:
		ruleID = sarifRuleCompromised
		msg = fmt.Sprintf("%s package %q shipped malicious versions (%s); %s is not one of them.", f.Ecosystem, f.Package, ids, f.Version)
	case f.Severity == scan.SeverityHigh:
		msg = fmt.Sprintf("%s package %q has malicious versions (%s) and %q is not pinned to a known-clean one.", f.Ecosystem, f.Package, ids, f.Version)
	}
	loc := sarifLocation{PhysicalLocation: sarifPhysical{ArtifactLocation: sarifArtifact{URI: uri}}}
	if f.Line > 0 {
		loc.PhysicalLocation.Region = &sarifRegion{StartLine: f.Line}
	}
	sum := sha256.Sum256([]byte(f.Ecosystem + "\x00" + f.Package + "\x00" + f.Version + "\x00" + uri + "\x00" + f.Reason))
	props := map[string]string{
		"ecosystem": f.Ecosystem,
		"package":   f.Package,
		"reason":    f.Reason,
		"severity":  f.Severity,
		"ids":       ids,
		"url":       f.URL,
	}
	if f.Version != "" {
		props["version"] = f.Version
	}
	if f.Campaign != "" {
		props["campaign"] = f.Campaign
	}
	level, secSev := sarifSeverity(f.Severity)
	props["security-severity"] = secSev
	return sarifResult{
		RuleID:              ruleID,
		Level:               level,
		Message:             sarifText{Text: msg},
		Locations:           []sarifLocation{loc},
		PartialFingerprints: map[string]string{fingerprintK: hex.EncodeToString(sum[:16])},
		Properties:          props,
	}
}

func sarifSeverity(sev string) (level, securitySeverity string) {
	switch sev {
	case scan.SeverityCritical:
		return "error", "9.8"
	case scan.SeverityHigh:
		return "error", "8.1"
	case scan.SeverityMedium:
		return "warning", "5.5"
	default:
		return "note", "3.1"
	}
}

// sarifURI returns a slash-separated path, relative to the working directory
// when possible, as code-scanning uploads expect repository-relative URIs.
func sarifURI(p string) string {
	if filepath.IsAbs(p) {
		if wd, err := os.Getwd(); err == nil {
			if rel, err := filepath.Rel(wd, p); err == nil && !strings.HasPrefix(rel, "..") {
				p = rel
			}
		}
	}
	return strings.TrimPrefix(filepath.ToSlash(filepath.Clean(p)), "./")
}
