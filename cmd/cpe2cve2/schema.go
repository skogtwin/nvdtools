// Package main was auto-generated.
// Command: jsonschema2go -gen go -goptr -gofmt -gopkg main -o schema.go https://csrc.nist.gov/schema/nvd/feed/1.1/nvd_cve_feed_json_1.1.schema
package main

// NVDCVEFeedJSON11DefCPEName was auto-generated.
// CPE name.
type NVDCVEFeedJSON11DefCPEName struct {
	Cpe22Uri         string `json:"cpe22Uri,omitempty"`
	Cpe23Uri         string `json:"cpe23Uri"`
	LastModifiedDate string `json:"lastModifiedDate,omitempty"`
}

// NVDCVEFeedJSON11DefCPEMatch was auto-generated.
// CPE match string or range.
type NVDCVEFeedJSON11DefCPEMatch struct {
	CPEName               []*NVDCVEFeedJSON11DefCPEName `json:"cpe_name,omitempty"`
	Cpe22Uri              string                        `json:"cpe22Uri,omitempty"`
	Cpe23Uri              string                        `json:"cpe23Uri"`
	VersionEndExcluding   string                        `json:"versionEndExcluding,omitempty"`
	VersionEndIncluding   string                        `json:"versionEndIncluding,omitempty"`
	VersionStartExcluding string                        `json:"versionStartExcluding,omitempty"`
	VersionStartIncluding string                        `json:"versionStartIncluding,omitempty"`
	Vulnerable            bool                          `json:"vulnerable"`
}

// NVDCVEFeedJSON11DefNode was auto-generated.
// Defines a node or sub-node in an NVD applicability statement.
type NVDCVEFeedJSON11DefNode struct {
	CPEMatch []*NVDCVEFeedJSON11DefCPEMatch `json:"cpe_match,omitempty"`
	Children []*NVDCVEFeedJSON11DefNode     `json:"children,omitempty"`
	Negate   bool                           `json:"negate,omitempty"`
	Operator string                         `json:"operator,omitempty"`
}

// NVDCVEFeedJSON11DefConfigurations was auto-generated.
// Defines the set of product configurations for a NVD applicability statement.
type NVDCVEFeedJSON11DefConfigurations struct {
	CVEDataVersion string                     `json:"CVE_data_version"`
	Nodes          []*NVDCVEFeedJSON11DefNode `json:"nodes,omitempty"`
}

// CVEJSON40Min11CVEDataMeta was auto-generated.
type CVEJSON40Min11CVEDataMeta struct {
	ASSIGNER string `json:"ASSIGNER"`
	ID       string `json:"ID"`
	STATE    string `json:"STATE,omitempty"`
}

// CVEJSON40Min11ProductVersionVersionData was auto-generated.
type CVEJSON40Min11ProductVersionVersionData struct {
	VersionAffected string `json:"version_affected,omitempty"`
	VersionValue    string `json:"version_value"`
}

// CVEJSON40Min11ProductVersion was auto-generated.
type CVEJSON40Min11ProductVersion struct {
	VersionData []*CVEJSON40Min11ProductVersionVersionData `json:"version_data"`
}

// CVEJSON40Min11Product was auto-generated.
type CVEJSON40Min11Product struct {
	ProductName string                        `json:"product_name"`
	Version     *CVEJSON40Min11ProductVersion `json:"version"`
}

// CVEJSON40Min11AffectsVendorVendorDataProduct was auto-generated.
type CVEJSON40Min11AffectsVendorVendorDataProduct struct {
	ProductData []*CVEJSON40Min11Product `json:"product_data"`
}

// CVEJSON40Min11AffectsVendorVendorData was auto-generated.
type CVEJSON40Min11AffectsVendorVendorData struct {
	Product    *CVEJSON40Min11AffectsVendorVendorDataProduct `json:"product"`
	VendorName string                                        `json:"vendor_name"`
}

// CVEJSON40Min11AffectsVendor was auto-generated.
type CVEJSON40Min11AffectsVendor struct {
	VendorData []*CVEJSON40Min11AffectsVendorVendorData `json:"vendor_data"`
}

// CVEJSON40Min11Affects was auto-generated.
type CVEJSON40Min11Affects struct {
	Vendor *CVEJSON40Min11AffectsVendor `json:"vendor"`
}

// CVEJSON40Min11LangString was auto-generated.
type CVEJSON40Min11LangString struct {
	Lang  string `json:"lang"`
	Value string `json:"value"`
}

// CVEJSON40Min11Description was auto-generated.
type CVEJSON40Min11Description struct {
	DescriptionData []*CVEJSON40Min11LangString `json:"description_data"`
}

// CVEJSON40Min11ProblemtypeProblemtypeData was auto-generated.
type CVEJSON40Min11ProblemtypeProblemtypeData struct {
	Description []*CVEJSON40Min11LangString `json:"description"`
}

// CVEJSON40Min11Problemtype was auto-generated.
type CVEJSON40Min11Problemtype struct {
	ProblemtypeData []*CVEJSON40Min11ProblemtypeProblemtypeData `json:"problemtype_data"`
}

// CVEJSON40Min11Reference was auto-generated.
type CVEJSON40Min11Reference struct {
	Name      string   `json:"name,omitempty"`
	Refsource string   `json:"refsource,omitempty"`
	Tags      []string `json:"tags,omitempty"`
	URL       string   `json:"url"`
}

// CVEJSON40Min11References was auto-generated.
type CVEJSON40Min11References struct {
	ReferenceData []*CVEJSON40Min11Reference `json:"reference_data"`
}

// CVEJSON40Min11 was auto-generated.
// Source: https://csrc.nist.gov/schema/nvd/feed/1.1/CVE_JSON_4.0_min_1.1.schema
type CVEJSON40Min11 struct {
	Affects     *CVEJSON40Min11Affects     `json:"affects,omitempty"`
	CVEDataMeta *CVEJSON40Min11CVEDataMeta `json:"CVE_data_meta"`
	DataFormat  string                     `json:"data_format"`
	DataType    string                     `json:"data_type"`
	DataVersion string                     `json:"data_version"`
	Description *CVEJSON40Min11Description `json:"description"`
	Problemtype *CVEJSON40Min11Problemtype `json:"problemtype"`
	References  *CVEJSON40Min11References  `json:"references"`
}

// CVSSV20 was auto-generated.
// Source: https://csrc.nist.gov/schema/nvd/feed/1.1/cvss-v2.0.json
type CVSSV20 struct {
	AccessComplexity           string  `json:"accessComplexity,omitempty"`
	AccessVector               string  `json:"accessVector,omitempty"`
	Authentication             string  `json:"authentication,omitempty"`
	AvailabilityImpact         string  `json:"availabilityImpact,omitempty"`
	AvailabilityRequirement    string  `json:"availabilityRequirement,omitempty"`
	BaseScore                  float64 `json:"baseScore"`
	CollateralDamagePotential  string  `json:"collateralDamagePotential,omitempty"`
	ConfidentialityImpact      string  `json:"confidentialityImpact,omitempty"`
	ConfidentialityRequirement string  `json:"confidentialityRequirement,omitempty"`
	EnvironmentalScore         float64 `json:"environmentalScore,omitempty"`
	Exploitability             string  `json:"exploitability,omitempty"`
	IntegrityImpact            string  `json:"integrityImpact,omitempty"`
	IntegrityRequirement       string  `json:"integrityRequirement,omitempty"`
	RemediationLevel           string  `json:"remediationLevel,omitempty"`
	ReportConfidence           string  `json:"reportConfidence,omitempty"`
	TargetDistribution         string  `json:"targetDistribution,omitempty"`
	TemporalScore              float64 `json:"temporalScore,omitempty"`
	VectorString               string  `json:"vectorString"`
	Version                    string  `json:"version"`
}

// NVDCVEFeedJSON11DefImpactBaseMetricV2 was auto-generated.
// CVSS V2.0 score.
type NVDCVEFeedJSON11DefImpactBaseMetricV2 struct {
	AcInsufInfo             bool     `json:"acInsufInfo,omitempty"`
	CVSSV2                  *CVSSV20 `json:"cvssV2,omitempty"`
	ExploitabilityScore     float64  `json:"exploitabilityScore,omitempty"`
	ImpactScore             float64  `json:"impactScore,omitempty"`
	ObtainAllPrivilege      bool     `json:"obtainAllPrivilege,omitempty"`
	ObtainOtherPrivilege    bool     `json:"obtainOtherPrivilege,omitempty"`
	ObtainUserPrivilege     bool     `json:"obtainUserPrivilege,omitempty"`
	Severity                string   `json:"severity,omitempty"`
	UserInteractionRequired bool     `json:"userInteractionRequired,omitempty"`
}

// CVSSV3x was auto-generated.
// Source: https://csrc.nist.gov/schema/nvd/feed/1.1/cvss-v3.x.json
type CVSSV3x struct {
	AttackComplexity              string  `json:"attackComplexity,omitempty"`
	AttackVector                  string  `json:"attackVector,omitempty"`
	AvailabilityImpact            string  `json:"availabilityImpact,omitempty"`
	AvailabilityRequirement       string  `json:"availabilityRequirement,omitempty"`
	BaseScore                     float64 `json:"baseScore"`
	BaseSeverity                  string  `json:"baseSeverity"`
	ConfidentialityImpact         string  `json:"confidentialityImpact,omitempty"`
	ConfidentialityRequirement    string  `json:"confidentialityRequirement,omitempty"`
	EnvironmentalScore            float64 `json:"environmentalScore,omitempty"`
	EnvironmentalSeverity         string  `json:"environmentalSeverity,omitempty"`
	ExploitCodeMaturity           string  `json:"exploitCodeMaturity,omitempty"`
	IntegrityImpact               string  `json:"integrityImpact,omitempty"`
	IntegrityRequirement          string  `json:"integrityRequirement,omitempty"`
	ModifiedAttackComplexity      string  `json:"modifiedAttackComplexity,omitempty"`
	ModifiedAttackVector          string  `json:"modifiedAttackVector,omitempty"`
	ModifiedAvailabilityImpact    string  `json:"modifiedAvailabilityImpact,omitempty"`
	ModifiedConfidentialityImpact string  `json:"modifiedConfidentialityImpact,omitempty"`
	ModifiedIntegrityImpact       string  `json:"modifiedIntegrityImpact,omitempty"`
	ModifiedPrivilegesRequired    string  `json:"modifiedPrivilegesRequired,omitempty"`
	ModifiedScope                 string  `json:"modifiedScope,omitempty"`
	ModifiedUserInteraction       string  `json:"modifiedUserInteraction,omitempty"`
	PrivilegesRequired            string  `json:"privilegesRequired,omitempty"`
	RemediationLevel              string  `json:"remediationLevel,omitempty"`
	ReportConfidence              string  `json:"reportConfidence,omitempty"`
	Scope                         string  `json:"scope,omitempty"`
	TemporalScore                 float64 `json:"temporalScore,omitempty"`
	TemporalSeverity              string  `json:"temporalSeverity,omitempty"`
	UserInteraction               string  `json:"userInteraction,omitempty"`
	VectorString                  string  `json:"vectorString"`
	Version                       string  `json:"version"`
}

// NVDCVEFeedJSON11DefImpactBaseMetricV3 was auto-generated.
// CVSS V3.x score.
type NVDCVEFeedJSON11DefImpactBaseMetricV3 struct {
	CVSSV3              *CVSSV3x `json:"cvssV3,omitempty"`
	ExploitabilityScore float64  `json:"exploitabilityScore,omitempty"`
	ImpactScore         float64  `json:"impactScore,omitempty"`
}

// NVDCVEFeedJSON11DefImpact was auto-generated.
// Impact scores for a vulnerability as found on NVD.
type NVDCVEFeedJSON11DefImpact struct {
	BaseMetricV2 *NVDCVEFeedJSON11DefImpactBaseMetricV2 `json:"baseMetricV2,omitempty"`
	BaseMetricV3 *NVDCVEFeedJSON11DefImpactBaseMetricV3 `json:"baseMetricV3,omitempty"`
}

// NVDCVEFeedJSON11DefCVEItem was auto-generated.
// Defines a vulnerability in the NVD data feed.
type NVDCVEFeedJSON11DefCVEItem struct {
	CVE              *CVEJSON40Min11                    `json:"cve"`
	Configurations   *NVDCVEFeedJSON11DefConfigurations `json:"configurations,omitempty"`
	Impact           *NVDCVEFeedJSON11DefImpact         `json:"impact,omitempty"`
	LastModifiedDate string                             `json:"lastModifiedDate,omitempty"`
	PublishedDate    string                             `json:"publishedDate,omitempty"`
}

// NVDCVEFeedJSON11 was auto-generated.
// Source: https://csrc.nist.gov/schema/nvd/feed/1.1/nvd_cve_feed_json_1.1.schema
type NVDCVEFeedJSON11 struct {
	CVEDataFormat       string                        `json:"CVE_data_format"`
	CVEDataNumberOfCVEs string                        `json:"CVE_data_numberOfCVEs,omitempty"`
	CVEDataTimestamp    string                        `json:"CVE_data_timestamp,omitempty"`
	CVEDataType         string                        `json:"CVE_data_type"`
	CVEDataVersion      string                        `json:"CVE_data_version"`
	CVEItems            []*NVDCVEFeedJSON11DefCVEItem `json:"CVE_Items"`
}
