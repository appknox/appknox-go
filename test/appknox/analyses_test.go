package appknox_test

import (
	"testing"

	"github.com/appknox/appknox-go/appknox"
)

func TestAnalyses(t *testing.T) {
	args := []string{"10"}
	analysesResponse, err := appknox.Analyses(args)
	if err != nil {
		t.Errorf(err.Error())
	}
	results := analysesResponse.Results
	if len(results) < 0 {
		t.Errorf("File shouldn't have zero analyses.")
	}
}
