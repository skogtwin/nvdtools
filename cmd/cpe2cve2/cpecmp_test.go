package main

import (
	"fmt"
	"testing"
)

func TestCPEmatch(t *testing.T) {
	tests := []struct {
		a, b string
		want bool
	}{
		{
			a:    `cpe:2.3:a:vendor:product:1.0:*:*:*:*:*:*:*`,
			b:    `cpe:2.3:a:vendor:product:1.0:*:*:*:*:*:*:*`,
			want: true,
		},
		{
			a:    `cpe:2.3:a:vendor:product:1.0:*:*:*:*:*:*:*`,
			b:    `cpe:2.3:a:vendor:product:1.1:*:*:*:*:*:*:*`,
			want: false,
		},
		{
			a:    "cpe:2.3:o:microsoft:windows_xp:-:sp2:*:*:*:*:*:*",
			b:    "cpe:2.3:o:microsoft:windows_xp:*:sp2:*:*:*:*:*:*",
			want: true,
		},
	}
	for _, test := range tests {
		t.Run(fmt.Sprintf("%s vs. %s", test.a, test.b), func(t *testing.T) {
			have := CPEmatch(test.a, test.b)
			if have != test.want {
				t.Fatalf("\nwant: %v\nhave: %v", test.want, have)
			}
		})
	}
}

func BenchmarkCPEmatch(b *testing.B) {
	src := `cpe:2.3:a:microsoft:*internet_ex??????:8.0.*:sp?:*:*:*:*:*:*`
	tgt := `cpe:2.3:a:microsoft:internet_explorer:8.1.6001:sp3:*:*:*:*:*:*`
	*safeMatching = false
	for i := 0; i < b.N; i++ {
		CPEmatch(src, tgt)
	}
}

func BenchmarkGetCPEversion(b *testing.B) {
	src := `cpe:2.3:a:microsoft:*internet_ex??????:8.0.*:sp?:*:*:*:*:*:*`
	for i := 0; i < b.N; i++ {
		getCPEversion(src)
	}
}
