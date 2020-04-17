package main

import (
	"bytes"
	"strings"
	"testing"
)

func BenchmarkProcess(b *testing.B) {
	feed, err := loadFeed(strings.NewReader(testDictJSONStr))
	if err != nil {
		b.Fatalf("could not load test feed: %v", err)
	}

	in := `cpe:/o:microsoft:windows_10:-::~~~~x64~,cpe:/a:adobe:flash_player:24.0.0.194
cpe:/o::centos_linux:7.5.1804,cpe:/a::chardet:2.2.1,cpe:/a::javapackages:1.0.0,cpe:/a::kitchen:1.1.1,cpe:/a::nose:1.3.7,cpe:/a::python-dateutil:1.5,cpe:/a::pytz:2016.10,cpe:/a::setuptools:0.9.8,cpe:/a::chardet:2.2.1,cpe:/a::javapackages:1.0.0,cpe:/a::kitchen:1.1.1,cpe:/a::nose:1.3.7,cpe:/a::python-dateutil:1.5,cpe:/a::pytz:2016.10,cpe:/a::setuptools:0.9.8
cpe:/o::centos_linux:7.5.1804,cpe:/a::chardet:2.2.1,cpe:/a::kitchen:1.1.1,cpe:/a::chardet:2.2.1,cpe:/a::kitchen:1.1.1,cpe:/a::chardet:2.2.1,cpe:/a::kitchen:1.1.1
`
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		var w bytes.Buffer
		r := strings.NewReader(in)
		process(&w, r, feed)
	}
}

var testDictJSONStr = `{
"CVE_data_type" : "CVE",
"CVE_data_format" : "MITRE",
"CVE_data_version" : "4.0",
"CVE_data_timestamp" : "2018-07-31T07:00Z",
"CVE_Items" : [
  {
    "cve" : {
      "data_type" : "CVE",
      "data_format" : "MITRE",
      "data_version" : "4.0",
      "CVE_data_meta" : {
        "ID" : "CVE-2016-0165",
        "ASSIGNER" : "cve@mitre.org"
      }
    },
    "configurations" : {
      "CVE_data_version" : "4.0",
      "nodes" : [
        {
          "operator" : "OR",
          "cpe_match" : [
            {
              "vulnerable" : true,
              "cpe23Uri" : "cpe:2.3:o:microsoft:windows_10:-:*:*:*:*:*:*:*"
            },
            {
              "vulnerable" : true,
              "cpe23Uri" : "cpe:2.3:o:microsoft:windows_10:1511:*:*:*:*:*:*:*"
            },
            {
              "vulnerable" : true,
              "cpe23Uri" : "cpe:2.3:o:microsoft:windows_7:*:sp1:*:*:*:*:*:*"
            },
            {
              "vulnerable" : true,
              "cpe23Uri" : "cpe:2.3:o:microsoft:windows_8.1:*:*:*:*:*:*:*:*"
            },
            {
              "vulnerable" : true,
              "cpe23Uri" : "cpe:2.3:o:microsoft:windows_rt_8.1:-:*:*:*:*:*:*:*"
            },
            {
              "vulnerable" : true,
              "cpe23Uri" : "cpe:2.3:o:microsoft:windows_server_2008:*:sp2:*:*:*:*:*:*"
            },
            {
              "vulnerable" : true,
              "cpe23Uri" : "cpe:2.3:o:microsoft:windows_server_2008:r2:sp1:*:*:*:*:*:*"
            },
            {
              "vulnerable" : true,
              "cpe23Uri" : "cpe:2.3:o:microsoft:windows_server_2012:-:*:*:*:*:*:*:*"
            },
            {
              "vulnerable" : true,
              "cpe23Uri" : "cpe:2.3:o:microsoft:windows_server_2012:r2:*:*:*:*:*:*:*"
            },
            {
              "vulnerable" : true,
              "cpe23Uri" : "cpe:2.3:o:microsoft:windows_vista:*:sp2:*:*:*:*:*:*"
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
        "ID" : "CVE-2666-1337",
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
              "cpe_match" : [
                {
                  "vulnerable" : true,
                  "cpe23Uri" : "cpe:2.3:o:microsoft:windows_10:*:*:*:*:*:*:*:*"
                }
              ]
            },
            {
              "operator" : "OR",
              "cpe_match" : [
                {
                  "vulnerable" : true,
                  "cpe23Uri" : "cpe:2.3:a:adobe:flash_player:24.0.0.194:*:*:*:*:*:*:*"
                }
              ]
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
        "ID" : "CVE-2666-6969",
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
              "cpe_match" : [
                {
                  "vulnerable" : true,
                  "cpe23Uri" : "cpe:2.3:o:microsoft:windows_10:*:*:*:*:*:*:*:*"
                }
              ]
            },
            {
              "operator" : "OR",
              "cpe_match" : [
                {
                  "vulnerable" : true,
                  "cpe23Uri" : "cpe:2.3:a:adobe:flash_player:24.0.1:*:*:*:*:*:*:*"
                }
              ]
            }
          ]
        }
      ]
    }
  }
]
}`
