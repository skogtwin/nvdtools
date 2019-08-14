package main

import (
	"fmt"

	"github.com/facebookincubator/nvdtools/wfn"
)

func process(in string, o *options) (string, error) {
	attr, err := wfn.Parse(in)
	if err != nil {
		return "", fmt.Errorf("bad CPE %q: %v", in, err)
	}
	if o.any2na {
		o.processAttributes(attr, replaceAttributeValue(wfn.Any, wfn.NA))
	}
	if o.na2any {
		o.processAttributes(attr, replaceAttributeValue(wfn.NA, wfn.Any))
	}
	var out string
	switch o.outBinding {
	case "uri":
		out = attr.BindToURI()
	case "fstr":
		out = attr.BindToFmtString()
	case "str":
		out = attr.String()
	default:
		panic("bad output binding") // input is validated, shouldn't reach here
	}
	return out, nil
}

func replaceAttributeValue(src, dst string) func(*string) error {
	return func(s *string) error {
		if *s == src {
			*s = dst
		}
		return nil
	}
}
