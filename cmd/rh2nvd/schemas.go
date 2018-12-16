package main

import (
	"encoding/json"
	"fmt"
)

// CVElist describes item in the list of all CVEs as reported by Red Hat security data API
// at https://access.redhat.com/labs/securitydataapi/cve.json.
type CVElist struct {
	CVE                 string   `json:"CVE"`
	Severity            string   `json:"severity"`
	PubDate             string   `json:"public_date"`
	Advisories          []string `json:"advisories"`
	Bugzilla            string   `json:"bugzilla"`
	BugzillaDescription string   `json:"bugzilla_description"`
	CVSS2score          float64  `json:"cvss_score"`
	CVSS3score          float64  `json:"cvss3_score"`
	CVSSvector          string   `json:"cvss_scoring_vector"`
	CWE                 string   `json:"CWE"`
	AffectedPackages    []string `json:"affected_packages"`
	ResourceURL         string   `json:"resource_url"`
}

// CVE describes the data about each particular CVE as reported by Red Hat security data API
// at https://access.redhat.com/labs/securitydataapi/cve/CVE-YYYY-ID.json.
type CVE struct {
	Name             string            `json:"name"`
	Severity         string            `json:"threat_severity"`   // The Severity of the flaw
	PubDate          string            `json:"public_date"`       // When the flaw became public in ISO 8601 format.
	Bugzilla         BugzillaData      `json:"bugzilla"`          // Id, URL, and Description of the bug in Red Hat’s Bugzilla.
	CVSS2            CVSS2data         `json:"cvss"`              // CVSSv2 score and metrics.
	CVSS3            CVSS3data         `json:"cvss3"`             // CVSSv3 score and metrics.
	CWE              string            `json:"cwe"`               // The CWE chain for this flaw.
	Details          []string          `json:"details"`           // Details about the flaw, possibly from Red Hat or Mitre.
	Ack              string            `json:"acknowledgement"`   // People or organizations that are being recognized.
	Mitigation       string            `json:"mitigation"`        // A way to fix or reduce the problem without updated software.
	AffectedReleases []AffectedRelease `json:"affected_releases"` // A released Erratum that fixes the flaw for a particular product.
	PackageStates    PackageStatesData `json:"package_state"`     // Information about a package / product where no fix has been released yet.
}

// BugzillaData holds the id, URL and description of the bug in Red Hat's Bugzilla.
type BugzillaData struct {
	ID, URL, Description string
}

// CVSS2data holds CVSSv2 score and metrics
type CVSS2data struct {
	BaseScore string `json:"cvss_base_score"`
	Vector    string `json:"cvss_scoring_vector"`
	Status    string `json:"status"`
}

// CVSS3data holds CVSSv3 score and metrics
type CVSS3data struct {
	BaseScore string `json:"cvss3_base_score"`
	Vector    string `json:"cvss3_scoring_vector"`
	Status    string `json:"status"`
}

// AffectedRelease describes a released Erratum that fixes the flaw for a particular product.
// Contains product name and CPE, and Erratum link, type, and release date. Optionally also
// includes "Package" information that describes the name and version of the src.rpm that fixes the issue (will not exist if
// multiple src.rpms are in the same Erratum).
type AffectedRelease struct {
	ProductName string `json:"product_name"`
	ReleaseDate string `json:"release_date"`
	Advisory    string `json:"advisory"`
	Package     string `json:"package"`
	CPE         string `json:"cpe"`
}

// PackageStatesData is a slice of PackageState objects.
// If there is only one package Red Hat serializes it as a JSON object, otherwise it becomes an array of objects.
// I need a custom slice type to define proper parsing of this case.
type PackageStatesData []PackageState

// PackageState holds the information about a package / product where no fix has been released yet.
// Contains product name and CPE, package (src.rpm) name, and fix state,
// which is one of ['Affected','Fix deferred','New','Not affected','Will not fix'].
type PackageState struct {
	ProductName string `json:"product_name"`
	FixState    string `json:"fix_state"`
	PackageName string `json:"package_name"`
	CPE         string `json:"cpe"`
}

// UnmarshalJSON implements json.Unmarshaler interface for PackageStatesData type.
func (ps *PackageStatesData) UnmarshalJSON(b []byte) error {
	// by convention input of []byte("null") is a no-op
	if string(b) == "null" {
		return nil
	}

	// first try unmarshal it as a list of objects
	var err1 error
	var packageStates []PackageState
	if err1 = json.Unmarshal(b, &packageStates); err1 == nil {
		*ps = packageStates
		return nil
	}

	// then as a single object
	var err2 error
	var packageState PackageState
	if err2 = json.Unmarshal(b, &packageState); err2 == nil {
		packageStates = append(packageStates, packageState)
		*ps = packageStates
		return nil
	}

	// give up if both attempts failed
	return fmt.Errorf("could not unmarshall PackageStatesData neither as single object nor as slice, the errors are: %v, %v", err1, err2)
}
