package rangectl

import (
	ps "github.com/4dogs-cn/TXPortMap/pkg/common/ipparser"
	"testing"
)

func TestParseIpv4RangeShorthandLastOctet(t *testing.T) {
	result, err := ParseIpv4Range("172.16.199.10-14")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	begin, _ := ps.ParseIPv4("172.16.199.10")
	end, _ := ps.ParseIPv4("172.16.199.14")

	if result.Begin != begin {
		t.Fatalf("expected begin %d got %d", begin, result.Begin)
	}

	if result.End != end {
		t.Fatalf("expected end %d got %d", end, result.End)
	}
}

func TestParseIpv4RangeShorthandInvalid(t *testing.T) {
	if _, err := ParseIpv4Range("172.16.199.10-9"); err == nil {
		t.Fatal("expected error for descending shorthand range")
	}
}
