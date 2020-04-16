package main

import (
	"bytes"
	"fmt"
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
	}
	feed, err := loadFeed(bytes.NewBufferString(testJSONdict))
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
  }
] }`
