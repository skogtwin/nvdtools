package main

import (
	"bufio"
	"encoding/json"
	"fmt"
	"io"
	"os"
)

func process(out io.Writer, in io.Reader, feed *Feed) error {
	scanner := bufio.NewScanner(in)
	for scanner.Scan() {
		cpe := scanner.Text()
		for _, cve := range feed.CVEItems {
			match := MatchCVE(cve, cpe)
			if len(match) != 0 {
				fmt.Fprintln(out, cpe, cve.CVE.CVEDataMeta.ID)
			}
		}
	}
	return nil
}

func main() {
	feedFile, err := os.Open(os.Args[1])
	if err != nil {
		sayErr(-1, "could not open vulnerability feed: %q", err)
	}
	defer feedFile.Close()

	feed, err := loadFeed(feedFile)
	if err != nil {
		sayErr(-1, "could not load vulnerability feed: %q", err)
	}
	if err := process(os.Stdout, os.Stdin, feed); err != nil {
		fmt.Fprintf(os.Stderr, "cpe2cve2: %v", err)
	}
}

func loadFeed(f io.Reader) (*Feed, error) {
	var feed Feed
	if err := json.NewDecoder(f).Decode(&feed); err != nil {
		return nil, err
	}
	return &feed, nil
}

func sayErr(status int, msg string, args ...interface{}) {
	fmt.Fprintf(os.Stderr, "cpe2cve: "+msg+"\n", args...)
	if status != 0 {
		os.Exit(status)
	}
}
