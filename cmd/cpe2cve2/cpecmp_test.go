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
	for i := 0; i < b.N; i++ {
		// checking error and result adds about 10% of runtime to this benchmark on my machine
		// and correctness is covered by tests, so skip it
		CPEmatch(src, tgt)
	}
}
