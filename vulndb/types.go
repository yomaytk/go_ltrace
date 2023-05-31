package types

type Severity uint8

const (
	LOW Severity = iota
	MEDIUM
	HIGH
	CRITiCAL
)

type CVSS struct {
	Severity Severity `json:"severity"`
	Score    float32  `json:"score"`
}

type CVE struct {
	Candidate   string `json:"candidata"`
	Description string `json:"description"`
	Priority    string `json:"priority"`
	CVSS        string `json:"cvss"`
}
