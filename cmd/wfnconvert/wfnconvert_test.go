package main

import (
	"bytes"
	"fmt"
	"strings"
	"testing"
)

func TestWfnconvert(t *testing.T) {
	defaultOptions := options{
		outBinding:       "fstr",
		attributes:       strFields{"all": true},
		invertAttributes: false,
		any2na:           false,
		na2any:           false,
		csvFields:        nil,
		csvComma:         ",",
	}
	cases := []struct {
		opts    *options
		in, out string
	}{
		{
			in:  "",
			out: "",
		},
		{
			in:  "cpe:/a:foo:bar:1.1\n",
			out: "cpe:2.3:a:foo:bar:1.1:*:*:*:*:*:*:*\n",
		},
		{
			opts: &options{
				outBinding:       "uri",
				attributes:       strFields{"vendor": true},
				invertAttributes: true,
				any2na:           true,
			},
			in:  "cpe:/a::bar:1.1\n",
			out: "cpe:/a::bar:1.1:-:-:-\n",
		},
		{
			opts: &options{
				outBinding:       "uri",
				attributes:       strFields{"vendor": true},
				invertAttributes: true,
				any2na:           true,
				csvFields:        intFields{1, 2},
				csvComma:         ",",
			},
			in: "field1.1,cpe:/a::bar:1.1,cpe:/o::linux_kernel:2.6.11,field1.4,field1.5\n" +
				"field2.1,cpe:/a::baz:1:-,cpe:/o:microsoft:windows:10:very_expensive,field2.4,field2.5\n",
			out: "field1.1,cpe:/a::bar:1.1:-:-:-,cpe:/o::linux_kernel:2.6.11:-:-:-,field1.4,field1.5\n" +
				"field2.1,cpe:/a::baz:1:-:-:-,cpe:/o:microsoft:windows:10:very_expensive:-:-,field2.4,field2.5\n",
		},
	}
	for n, c := range cases {
		n, c := n, c
		t.Run(fmt.Sprintf("case_%d", n), func(t *testing.T) {
			var out strings.Builder
			in := bytes.NewBufferString(c.in)
			opts := c.opts
			if opts == nil {
				opts = &defaultOptions
			}
			if err := wfnconvert(in, &out, opts); err != nil {
				t.Fatal(err)
			}
			if out.String() != c.out {
				t.Fatalf("unexpected output:\nwant: %q\nhave: %q", c.out, out.String())
			}
		})
	}
}
