package main

import (
	"bytes"
	"fmt"
	"strings"
	"testing"
)

func TestMatchConfiguration(t *testing.T) {
	*safeMatching = true
	cases := []struct {
		Rule      int
		Inventory []string
		Matches   []string
	}{
		{},
		{
			Inventory: []string{
				"cpe:2.3:o:linux:linux_kernel:2.6.1:*:*:*:*:*:*:*",
				"cpe:2.3:a:djvulibre_project:djvulibre:3.5.11:*:*:*:*:*:*:*",
			},
		},
		{
			Rule: 0,
			Inventory: []string{
				"cpe:2.3:o:microsoft:windows_xp:*:sp3:*:*:*:*:*:*",
				"cpe:2.3:a:microsoft:ie:6.1:*:*:*:*:*:*:*",
				"cpe:2.3:a:facebook:styx:0.1:*:*:*:*:*:*:*",
			},
			Matches: []string{
				"cpe:2.3:o:microsoft:windows_xp:*:sp3:*:*:*:*:*:*",
				"cpe:2.3:a:microsoft:ie:6.1:*:*:*:*:*:*:*",
			},
		},
		{
			Rule: 1,
			Inventory: []string{
				"cpe:2.3:a:microsoft:ie:3.9:*:*:*:*:*:*:*",
				"cpe:2.3:a:microsoft:ie:4.0:*:*:*:*:*:*:*",
				"cpe:2.3:a:microsoft:ie:5.4:*:*:*:*:*:*:*",
				"cpe:2.3:a:microsoft:ie:6.0:*:*:*:*:*:*:*",
			},
			Matches: []string{
				"cpe:2.3:a:microsoft:ie:4.0:*:*:*:*:*:*:*",
				"cpe:2.3:a:microsoft:ie:5.4:*:*:*:*:*:*:*",
			},
		},
		{
			Rule: 2,
			Inventory: []string{
				"cpe:2.3:a:mozilla:firefox:64.1:*:*:*:*:*:*:*",
			},
		},
		{
			Rule: 3,
			Inventory: []string{
				"cpe:2.3:o:netbsd:netbsd:1.1:*:*:*:*:*:*:*",
				"cpe:2.3:a:microsoft:winsock:2.0:*:*:*:*:*:*:*",
			},
			Matches: []string{
				"cpe:2.3:o:netbsd:netbsd:1.1:*:*:*:*:*:*:*",
			},
		},
		{
			Rule: 4,
			Inventory: []string{
				"cpe:2.3:o:microsoft:windows_xp:*:sp2:*:*:*:*:*:*",
			},
			Matches: []string{
				"cpe:2.3:o:microsoft:windows_xp:*:sp2:*:*:*:*:*:*",
			},
		},
	}
	feed, err := loadFeed(strings.NewReader(testJSONdict))
	if err != nil {
		t.Fatal(err)
	}
	for i, c := range cases {
		t.Run(fmt.Sprintf("%d", i+1), func(t *testing.T) {
			mm := MatchCVE(feed.CVEItems[c.Rule], c.Inventory...)
			if len(mm) != len(c.Matches) {
				t.Fatalf("expected %d matches, got %d matches", len(c.Matches), len(mm))
			}
			if len(mm) > 0 && !hasAll(mm, c.Matches) {
				t.Fatalf("wrong match: expected %v, got %v", c.Matches, mm)
			}
		})
	}
}

func BenchmarkMatchJSON(b *testing.B) {
	*safeMatching = false
	inventory := []string{
		"cpe:2.3:o:microsoft:windows_xp:*:sp3:*:*:*:*:*:*",
		"cpe:2.3:a:microsoft:ie:6.1:*:*:*:*:*:*:*",
		"cpe:2.3:a:facebook:styx:0.1:*:*:*:*:*:*:*",
	}
	feed, err := loadFeed(bytes.NewBufferString(testJSONdict))
	if err != nil {
		b.Fatal(err)
	}
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		mm := MatchCVE(feed.CVEItems[0], inventory...)
		if len(mm) == 0 {
			b.Fatal("expected Match to match, it did not")
		}
	}
}

func hasAll(haystack, needle []string) bool {
	if len(haystack) != len(needle) {
		return false
	}
	set := make(map[string]bool)
	for _, s := range haystack {
		set[s] = true
	}
	for _, s := range needle {
		if !set[s] {
			return false
		}
	}
	return true
}

var testJSONdict = `{
"CVE_data_type" : "CVE",
"CVE_data_format" : "MITRE",
"CVE_data_version" : "4.0",
"CVE_data_numberOfCVEs" : "7083",
"CVE_data_timestamp" : "2018-07-31T07:00Z",
"CVE_Items" : [
  {
    "cve" : {
      "data_type" : "CVE",
      "data_format" : "MITRE",
      "data_version" : "4.0",
      "CVE_data_meta" : {
        "ID" : "TESTVE-2018-0001",
        "ASSIGNER" : "cve@mitre.org"
      }
    },
    "configurations" : {
      "CVE_data_version" : "4.0",
      "nodes" : [
        {
          "operator" : "AND",
          "children" : [
            {
              "operator" : "OR",
              "cpe_match" : [ {
                "vulnerable" : true,
                  "cpe22Uri" : "cpe:/a:microsoft:ie:6.1",
                  "cpe23Uri" : "cpe:2.3:a:microsoft:ie:6.1:*:*:*:*:*:*:*"
              } ]
            },
            {
              "operator" : "OR",
              "cpe_match" : [ {
                "vulnerable" : true,
                "cpe22Uri" : "cpe:/o:microsoft:windows_xp::sp3",
                "cpe23Uri" : "cpe:2.3:o:microsoft:windows_xp:*:sp3:*:*:*:*:*:*"
              } ]
            }
          ]
        }
      ]
    }
  },
  {
    "cve" : {
      "data_type" : "CVE",
      "data_format" : "MITRE",
      "data_version" : "4.0",
      "CVE_data_meta" : {
        "ID" : "TESTVE-2018-0002",
        "ASSIGNER" : "cve@mitre.org"
      }
    },
    "configurations" : {
      "CVE_data_version" : "4.0",
      "nodes" : [
        {
          "operator" : "OR",
          "cpe_match" : [ {
            "vulnerable" : true,
            "cpe22Uri" : "cpe:/a:microsoft:ie",
            "cpe23Uri" : "cpe:2.3:a:microsoft:ie:*:*:*:*:*:*:*:*",
            "versionStartIncluding" : "4.0",
            "versionEndExcluding" : "6.0"
          } ]
        }
      ]
    }
  },
  {
    "cve": {
      "data_format": "MITRE",
      "data_type": "CVE",
      "data_version": "4.0",
      "CVE_data_meta": {
        "ASSIGNER": "cve@mitre.org",
        "ID": "CVE-2002-2436"
      }
    },
    "configurations": {
      "CVE_data_version": "4.0",
      "nodes": [
        {
          "cpe_match": [
            {
              "cpe23Uri": "cpe:2.3:a:mozilla:firefox:*:*:*:*:*:*:*:*",
              "versionEndIncluding": "64.0",
              "vulnerable": true
            }
          ],
          "operator": "OR"
        }
      ]
    }
  },
  {
    "cve": {
      "data_format": "MITRE",
      "data_type": "CVE",
      "data_version": "4.0",
      "CVE_data_meta": {
        "ASSIGNER": "cve@mitre.org",
        "ID": "CVE-2002-2436"
      }
    },
    "configurations" : {
      "CVE_data_version" : "4.0",
      "nodes" : [ {
        "operator" : "AND",
        "children" : [ {
          "operator" : "OR",
          "cpe_match" : [ {
            "vulnerable" : true,
            "cpe23Uri" : "cpe:2.3:o:cisco:ios:7000:*:*:*:*:*:*:*"
          } ]
        }, {
          "operator" : "OR",
          "cpe_match" : [ {
            "vulnerable" : true,
            "cpe23Uri" : "cpe:2.3:a:gnu:inet:5.01:*:*:*:*:*:*:*"
          }, {
            "vulnerable" : true,
            "cpe23Uri" : "cpe:2.3:a:microsoft:winsock:2.0:*:*:*:*:*:*:*"
          } ]
        } ]
      }, {
        "operator" : "OR",
        "cpe_match" : [ {
          "vulnerable" : true,
          "cpe23Uri" : "cpe:2.3:o:hp:hp-ux:9.00:*:*:*:*:*:*:*"
        }, {
          "vulnerable" : true,
          "cpe23Uri" : "cpe:2.3:o:hp:hp-ux:9.01:*:*:*:*:*:*:*"
        }, {
          "vulnerable" : true,
          "cpe23Uri" : "cpe:2.3:o:hp:hp-ux:9.03:*:*:*:*:*:*:*"
        }, {
          "vulnerable" : true,
          "cpe23Uri" : "cpe:2.3:o:hp:hp-ux:9.04:*:*:*:*:*:*:*"
        }, {
          "vulnerable" : true,
          "cpe23Uri" : "cpe:2.3:o:hp:hp-ux:9.05:*:*:*:*:*:*:*"
        }, {
          "vulnerable" : true,
          "cpe23Uri" : "cpe:2.3:o:hp:hp-ux:9.07:*:*:*:*:*:*:*"
        }, {
          "vulnerable" : true,
          "cpe23Uri" : "cpe:2.3:o:hp:hp-ux:10.00:*:*:*:*:*:*:*"
        }, {
          "vulnerable" : true,
          "cpe23Uri" : "cpe:2.3:o:hp:hp-ux:10.01:*:*:*:*:*:*:*"
        }, {
          "vulnerable" : true,
          "cpe23Uri" : "cpe:2.3:o:hp:hp-ux:10.10:*:*:*:*:*:*:*"
        }, {
          "vulnerable" : true,
          "cpe23Uri" : "cpe:2.3:o:hp:hp-ux:10.16:*:*:*:*:*:*:*"
        }, {
          "vulnerable" : true,
          "cpe23Uri" : "cpe:2.3:o:hp:hp-ux:10.20:*:*:*:*:*:*:*"
        }, {
          "vulnerable" : true,
          "cpe23Uri" : "cpe:2.3:o:hp:hp-ux:10.24:*:*:*:*:*:*:*"
        }, {
          "vulnerable" : true,
          "cpe23Uri" : "cpe:2.3:o:hp:hp-ux:10.30:*:*:*:*:*:*:*"
        }, {
          "vulnerable" : true,
          "cpe23Uri" : "cpe:2.3:o:hp:hp-ux:11.00:*:*:*:*:*:*:*"
        }, {
          "vulnerable" : true,
          "cpe23Uri" : "cpe:2.3:o:microsoft:windows_95:*:*:*:*:*:*:*:*"
        }, {
          "vulnerable" : true,
          "cpe23Uri" : "cpe:2.3:o:microsoft:windows_nt:4.0:*:*:*:*:*:*:*"
        }, {
          "vulnerable" : true,
          "cpe23Uri" : "cpe:2.3:o:netbsd:netbsd:1.0:*:*:*:*:*:*:*"
        }, {
          "vulnerable" : true,
          "cpe23Uri" : "cpe:2.3:o:netbsd:netbsd:1.1:*:*:*:*:*:*:*"
        }, {
          "vulnerable" : true,
          "cpe23Uri" : "cpe:2.3:o:sun:sunos:4.1.3u1:*:*:*:*:*:*:*"
        }, {
          "vulnerable" : true,
          "cpe23Uri" : "cpe:2.3:o:sun:sunos:4.1.4:*:*:*:*:*:*:*"
        } ]
      } ]
    }
  },
  {
    "cve" : {
      "data_type" : "CVE",
      "data_format" : "MITRE",
      "data_version" : "4.0",
      "CVE_data_meta" : {
        "ID" : "CVE-2010-0025",
        "ASSIGNER" : "cve@mitre.org"
      },
      "problemtype" : {
        "problemtype_data" : [ {
          "description" : [ {
            "lang" : "en",
            "value" : "CWE-200"
          } ]
        } ]
      },
      "references" : {
        "reference_data" : [ {
          "url" : "http://secunia.com/advisories/39253",
          "name" : "39253",
          "refsource" : "SECUNIA",
          "tags" : [ "Third Party Advisory" ]
        }, {
          "url" : "http://www.us-cert.gov/cas/techalerts/TA10-103A.html",
          "name" : "TA10-103A",
          "refsource" : "CERT",
          "tags" : [ "Third Party Advisory", "US Government Resource" ]
        }, {
          "url" : "https://docs.microsoft.com/en-us/security-updates/securitybulletins/2010/ms10-024",
          "name" : "MS10-024",
          "refsource" : "MS",
          "tags" : [ "Patch", "Vendor Advisory" ]
        }, {
          "url" : "https://oval.cisecurity.org/repository/search/definition/oval%3Aorg.mitre.oval%3Adef%3A12175",
          "name" : "oval:org.mitre.oval:def:12175",
          "refsource" : "OVAL",
          "tags" : [ "Third Party Advisory" ]
        } ]
      },
      "description" : {
        "description_data" : [ {
          "lang" : "en",
          "value" : "The SMTP component in Microsoft Windows 2000 SP4, XP SP2 and SP3, Server 2003 SP2, and Server 2008 Gold, SP2, and R2, and Exchange Server 2000 SP3, does not properly allocate memory for SMTP command replies, which allows remote attackers to read fragments of e-mail messages by sending a series of invalid commands and then sending a STARTTLS command, aka \"SMTP Memory Allocation Vulnerability.\""
        } ]
      }
    },
    "configurations" : {
      "CVE_data_version" : "4.0",
      "nodes" : [ {
        "operator" : "OR",
        "cpe_match" : [ {
          "vulnerable" : true,
          "cpe23Uri" : "cpe:2.3:o:microsoft:windows_2000:-:sp4:*:*:*:*:*:*"
        } ]
      }, {
        "operator" : "OR",
        "cpe_match" : [ {
          "vulnerable" : true,
          "cpe23Uri" : "cpe:2.3:o:microsoft:windows_xp:-:sp2:*:*:*:*:*:*"
        }, {
          "vulnerable" : true,
          "cpe23Uri" : "cpe:2.3:o:microsoft:windows_xp:-:sp2:*:*:*:*:x64:*"
        }, {
          "vulnerable" : true,
          "cpe23Uri" : "cpe:2.3:o:microsoft:windows_xp:-:sp3:*:*:*:*:*:*"
        } ]
      }, {
        "operator" : "OR",
        "cpe_match" : [ {
          "vulnerable" : true,
          "cpe23Uri" : "cpe:2.3:o:microsoft:windows_2003_server:-:sp2:*:*:*:*:itanium:*"
        }, {
          "vulnerable" : true,
          "cpe23Uri" : "cpe:2.3:o:microsoft:windows_server_2003:-:sp2:*:*:*:*:*:*"
        } ]
      }, {
        "operator" : "OR",
        "cpe_match" : [ {
          "vulnerable" : true,
          "cpe23Uri" : "cpe:2.3:o:microsoft:windows_server_2008:-:*:*:*:*:*:x64:*"
        }, {
          "vulnerable" : true,
          "cpe23Uri" : "cpe:2.3:o:microsoft:windows_server_2008:-:r2:*:*:*:*:x64:*"
        }, {
          "vulnerable" : true,
          "cpe23Uri" : "cpe:2.3:o:microsoft:windows_server_2008:-:sp2:*:*:*:*:*:*"
        }, {
          "vulnerable" : true,
          "cpe23Uri" : "cpe:2.3:o:microsoft:windows_server_2008:-:sp2:*:*:*:*:x64:*"
        }, {
          "vulnerable" : true,
          "cpe23Uri" : "cpe:2.3:o:microsoft:windows_server_2008:-:sp2:*:*:*:*:x86:*"
        } ]
      }, {
        "operator" : "OR",
        "cpe_match" : [ {
          "vulnerable" : true,
          "cpe23Uri" : "cpe:2.3:a:microsoft:exchange_server:2000:sp3:*:*:*:*:*:*"
        }, {
          "vulnerable" : true,
          "cpe23Uri" : "cpe:2.3:a:microsoft:exchange_server:2003:sp2:*:*:*:*:*:*"
        }, {
          "vulnerable" : true,
          "cpe23Uri" : "cpe:2.3:a:microsoft:exchange_server:2007:sp1:*:*:*:*:x64:*"
        }, {
          "vulnerable" : true,
          "cpe23Uri" : "cpe:2.3:a:microsoft:exchange_server:2007:sp2:*:*:*:*:x64:*"
        }, {
          "vulnerable" : true,
          "vulnerable" : true,
          "cpe23Uri" : "cpe:2.3:a:microsoft:exchange_server:2007:sp2:*:*:*:*:x64:*"
        }, {
          "vulnerable" : true,
          "cpe23Uri" : "cpe:2.3:a:microsoft:exchange_server:2010:-:*:*:*:*:x64:*"
        } ]
      } ]
    },
    "impact" : {
      "baseMetricV2" : {
        "cvssV2" : {
          "version" : "2.0",
          "vectorString" : "AV:N/AC:L/Au:N/C:P/I:N/A:N",
          "accessVector" : "NETWORK",
          "accessComplexity" : "LOW",
          "authentication" : "NONE",
          "confidentialityImpact" : "PARTIAL",
          "integrityImpact" : "NONE",
          "availabilityImpact" : "NONE",
          "baseScore" : 5.0
        },
        "severity" : "MEDIUM",
        "exploitabilityScore" : 10.0,
        "impactScore" : 2.9,
        "obtainAllPrivilege" : false,
        "obtainUserPrivilege" : false,
        "obtainOtherPrivilege" : false,
        "userInteractionRequired" : false
      }
    },
    "publishedDate" : "2010-04-14T16:00Z",
    "lastModifiedDate" : "2020-04-09T13:24Z"
  }
] }`
