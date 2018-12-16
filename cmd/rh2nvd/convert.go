package main

import "fmt"

func convert(cves map[string]*CVE) {
	for _, v := range cves {
		fmt.Printf("%s: p:%d, r:%d\n", v.Name, len(v.PackageStates), len(v.AffectedReleases))
	}
	fmt.Printf("%d total\n", len(cves))
}
