package simple

import (
	"fmt"
	"testing"
)

func TestFromVectorString(t *testing.T) {
	cases := []struct {
		in         string
		out        Vector
		shouldFail bool
	}{
		{
			in:  "CVSS:3.0/AV:N/AC:L/PR:H/UI:N/S:U/C:L/I:L/A:N",
			out: Vector{"AV": "N", "AC": "L", "PR": "H", "UI": "N", "S": "U", "C": "L", "I": "L", "A": "N"},
		},
	}

	for n, c := range cases {
		t.Run(fmt.Sprintf("case#%d", n), func(t *testing.T) {
			v, err := FromVectorString(c.in)
			if err != nil {
				if c.shouldFail {
					return
				}
				t.Fatalf("unexpected error: %v", err)
			}
			if !sameVector(c.out, v) {
				t.Fatalf("wrong output:\nwant %v\nhave: %v", c.out, v)
			}
		})
	}
}

func BenchmarkFromVectorString(b *testing.B) {
	s := "AV:P/AC:H/PR:L/UI:R/S:C/C:L/I:L/A:L/E:U/RL:T/RC:R/CR:H/IR:M/AR:L/MAV:P/MAC:H/MPR:L/MUI:R/MS:U/MC:L/MI:L/MA:H"
	for i := 0; i < b.N; i++ {
		v, err := FromVectorString(s)
		if err != nil {
			b.Fatal(err)
		}
		_ = v
	}
}

func sameVector(v1, v2 Vector) bool {
	for k, v := range v1 {
		if q, ok := v2[k]; !ok && v != "X" || ok && q != v {
			return false
		}
	}
	for k, v := range v2 {
		if q, ok := v1[k]; !ok && v != "X" || ok && q != v {
			return false
		}
	}
	return true
}
