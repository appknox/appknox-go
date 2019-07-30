package appknox

import (
	"context"
	"fmt"
	"net/http"
	"reflect"
	"testing"
)

func TestSubmission_marshall(t *testing.T) {
	testJSONMarshal(t, &Submission{}, "{}")

	u := &Submission{
		ID:          1,
		Status:      "s",
		File:        1,
		PackageName: "p",
		Reason:      "r",
	}
	want := `{
		"id": 1,
		"status": "s",
		"file": 1,
		"package_name": "p",
		"reason": "r"
	}`
	testJSONMarshal(t, u, want)
}

func TestSubmissionsService_GetByID(t *testing.T) {
	client, mux, _, teardown := setup()
	defer teardown()

	mux.HandleFunc("/api/submissions/1", func(w http.ResponseWriter, r *http.Request) {
		testMethod(t, r, "GET")
		fmt.Fprint(w, `{"id":1}`)
	})

	submission, _, err := client.Submissions.GetByID(context.Background(), 1)
	if err != nil {
		t.Errorf("Submissions.GetByID returned error: %v", err)
	}

	want := &Submission{ID: 1}
	if !reflect.DeepEqual(submission, want) {
		t.Errorf("Submissions.GetByID returned %+v, want %+v", submission, want)
	}
}
