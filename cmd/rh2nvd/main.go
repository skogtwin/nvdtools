package main

import (
	"flag"
	"log"
	"net/url"
)

var cveListURL = flag.String("url", "https://access.redhat.com/labs/securitydataapi/cve.json", "URL CVEs list is served at")
var downloadPath = flag.String("store_source", "", "directory to store the source data, empty string to disable")

func main() {
	flag.Parse()
	url, err := url.Parse(*cveListURL)
	if err != nil {
		log.Fatalf("could not parse url %q: %v", url, err)
	}
	cves, err := download(url, *downloadPath)
	if err != nil {
		log.Fatalf("could not fetch CVE feed: %v", err)
	}
	convert(cves)
}
