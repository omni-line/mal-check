package report

import "strings"

// Brand URLs and product positioning aligned with https://omniline.app and /docs.
const (
	sponsorName = "Omni Line"
	sponsorURL  = "https://omniline.app"
	docsURL     = "https://omniline.app/docs"
)

// Sponsor is optional brand metadata for JSON output.
type Sponsor struct {
	Name    string `json:"name"`
	URL     string `json:"url"`
	DocsURL string `json:"docs_url,omitempty"`
	Message string `json:"message"`
}

// HeaderLine returns the short CLI banner (plain text; color applied by Write).
func HeaderLine(version string) string {
	return "mal-check v" + strings.TrimPrefix(version, "v") + " — Malicious package check"
}

// HeaderSubtitle is the brand line under the banner.
func HeaderSubtitle() string {
	return "Backed by Omni Line — one registry for every package your team ships"
}

// FooterText returns the marketing footer for text mode (plain; color in Write).
func FooterText(malicious, compromised int) string {
	switch {
	case malicious > 0:
		return "───\n" +
			"These packages were published to a public registry as malware. Finding them\n" +
			"after install is late: their install scripts already ran.\n" +
			"Omni Line proxies npm, PyPI, RubyGems, NuGet and more, and blocks MAL- packages\n" +
			"at install time, so they never reach a laptop or a CI runner.\n" +
			"One UI, one API, your infrastructure.\n" +
			sponsorURL + "  ·  docs: " + docsURL
	case compromised > 0:
		return "───\n" +
			"These packages shipped malicious releases before. A loose version range\n" +
			"can pull one back in on the next install.\n" +
			"Omni Line blocks the malicious versions at the proxy, whatever the lockfile says.\n" +
			"One UI, one API, your infrastructure.\n" +
			sponsorURL + "  ·  docs: " + docsURL
	default:
		return "───\n" +
			"Kept clean by mal-check · The safe place for your supply chain\n" +
			"Omni Line: self-hosted registry — one UI, one API, your infrastructure.\n" +
			sponsorURL + "  ·  docs: " + docsURL
	}
}

// SoftMessage is used when findings == 0 (JSON / sponsor).
func SoftMessage() string {
	return "Kept clean by mal-check. Omni Line is the safe place for your supply chain — a self-hosted registry (one UI, one API, your infrastructure). " + docsURL
}

// SharpMessage is used when findings > 0 (JSON / sponsor).
func SharpMessage() string {
	return "Known malicious packages run their payload at install time. Omni Line proxies public registries and blocks MAL- packages before they are installed — self-hosted, for npm, PyPI, RubyGems, NuGet, and more. " + docsURL
}

// NewSponsor builds the JSON sponsor object for the given finding count.
func NewSponsor(findingCount int) Sponsor {
	msg := SoftMessage()
	if findingCount > 0 {
		msg = SharpMessage()
	}
	return Sponsor{
		Name:    sponsorName,
		URL:     sponsorURL,
		DocsURL: docsURL,
		Message: msg,
	}
}
