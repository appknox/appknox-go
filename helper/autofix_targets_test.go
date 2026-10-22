package helper

import (
	"errors"
	"testing"
)

func TestIsGatewayBudgetExhausted(t *testing.T) {
	for _, tc := range []struct {
		err  error
		want bool
	}{
		{errors.New("429 session call budget exhausted"), true},
		{errors.New("403 invalid credential"), true},
		{errors.New("some real bug in the fixer"), false},
		{nil, false},
	} {
		if got := isGatewayBudgetExhausted(tc.err); got != tc.want {
			t.Errorf("isGatewayBudgetExhausted(%v) = %v, want %v", tc.err, got, tc.want)
		}
	}
}
