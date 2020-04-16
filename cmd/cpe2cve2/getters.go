package main

type Feed = NVDCVEFeedJSON11
type CVE = NVDCVEFeedJSON11DefCVEItem
type Node = NVDCVEFeedJSON11DefNode
type Match = NVDCVEFeedJSON11DefCPEMatch

func (cve CVE) Nodes() []*Node {
	return cve.Configurations.Nodes
}
