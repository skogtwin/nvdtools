package main

import (
	"encoding/csv"
	"encoding/json"
	"fmt"
	"io"
	"os"
	"strings"
)

func process(out io.Writer, in io.Reader, feed *Feed) (err error) {
	r := csv.NewReader(in)
	r.Comma = '\t'
	w := csv.NewWriter(out)
	w.Comma = '\t'
	defer func() {
		w.Flush()
		if err2 := w.Error(); err == nil {
			err = err2
		}
	}()
	for {
		rec, err := r.Read()
		if err != nil {
			if err == io.EOF {
				return nil
			}
			return err
		}
		cpes := strings.Split(rec[len(rec)-1], ",")
		for _, cve := range feed.CVEItems {
			match := MatchCVE(cve, cpes...)
			if len(match) != 0 {
				rec = append(rec, cve.CVE.CVEDataMeta.ID, strings.Join(match, ","))
				w.Write(rec)
			}
		}
	}
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
