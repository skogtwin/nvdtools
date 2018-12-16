package main

import (
	"bytes"
	"encoding/json"
	"fmt"
	"io"
	"io/ioutil"
	"log"
	"net/http"
	"net/url"
	"os"
	"path/filepath"
	"sync"
)

func download(rootURL *url.URL, path string) (map[string]*CVE, error) {
	listJSON, err := fetchAndStore(rootURL.String(), path, "cve.json")
	if err != nil {
		return nil, fmt.Errorf("could not fetch %q: %v", rootURL.String(), err)
	}

	var list []CVElist
	if err = json.Unmarshal(listJSON, &list); err != nil {
		return nil, fmt.Errorf("could not unmarshal %q: %v", rootURL.String(), err)
	}

	cvesChan := make(chan *CVE)
	done := make(chan struct{})
	cves := make(map[string]*CVE)
	go func() {
		for cve := range cvesChan {
			cves[cve.Name] = cve
		}
		close(done)
	}()
	var wg sync.WaitGroup
	for _, cve := range list {
		cve := cve
		if cve.ResourceURL == "" {
			continue
		}
		wg.Add(1)
		go func() {
			if data, err := fetchAndParseCVE(cve, path); err != nil {
				log.Print(err)
			} else {
				cvesChan <- data
			}
			wg.Done()
		}()
	}
	wg.Wait()
	close(cvesChan)
	<-done

	return cves, nil
}

func fetchAndParseCVE(item CVElist, path string) (*CVE, error) {
	var err error
	var cveJSON []byte

	if needsFetching(item.CVE, path) {
		if cveJSON, err = fetchAndStore(item.ResourceURL, path, fmt.Sprintf("%s.json", item.CVE)); err != nil {
			return nil, fmt.Errorf("could not fetch %q: %v", item.ResourceURL, err)
		}
	} else {
		if cveJSON, err = ioutil.ReadFile(pathToStoredCVE(path, item.CVE)); err != nil {
			return nil, fmt.Errorf("could not retrieve cached copy of %q: %v", item.ResourceURL, err)
		}
	}

	var cve CVE
	if err = json.Unmarshal(cveJSON, &cve); err != nil {
		return nil, fmt.Errorf("could not unmarshall %q: %v", item.ResourceURL, err)
	}

	return &cve, nil
}

// fetchAndStore fetches the URI and returns a copy of response body.
// If path is not an empty string it also stores response body at path/file.
func fetchAndStore(uri, path, file string) ([]byte, error) {
	body := new(bytes.Buffer)
	if path != "" {
		if err := os.MkdirAll(path, 0775); err != nil {
			return nil, fmt.Errorf("could not create directory %q: %v", path, err)
		}
	}

	resp, err := http.Get(uri)
	if err != nil {
		return nil, fmt.Errorf("could not download root feed from %q: %v", uri, err)
	}
	defer resp.Body.Close()

	if path == "" {
		io.Copy(body, resp.Body)
		return body.Bytes(), nil
	}

	f, err := os.OpenFile(filepath.Join(path, file), os.O_WRONLY|os.O_CREATE, 0664)
	if err != nil {
		return nil, fmt.Errorf("could not open %q for writing: %v", path, err)
	}
	defer f.Close()
	mw := io.MultiWriter(f, body)
	if _, err = io.Copy(mw, resp.Body); err != nil {
		return nil, fmt.Errorf("could not write the file: %v", err)
	}
	return body.Bytes(), nil
}

func pathToStoredCVE(path, cve string) string {
	return filepath.Join(path, fmt.Sprintf("%s.json", cve))

}

func needsFetching(cve, path string) bool {
	_, err := os.Stat(pathToStoredCVE(path, cve))
	if err != nil && os.IsNotExist(err) {
		return true
	}
	return false
}
