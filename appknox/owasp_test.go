package appknox

import (
	"context"
	"fmt"
	"net/http"
	"reflect"
	"testing"
)

func TestOWASP_marshall(t *testing.T) {
	testJSONMarshal(t, &OWASP{}, "{}")

	u := &OWASP{
		Code:        "c",
		Description: "d",
		ID:          "i",
		Title:       "t",
		Year:        1,
	}
	want := `{
		"code": "c",
		"description": "d",
		"id": "i",
		"title": "t",
		"year": 1
	}`
	testJSONMarshal(t, u, want)
}

func TestOWASPService_GetByID(t *testing.T) {
	client, mux, _, teardown := setup()
	defer teardown()

	mux.HandleFunc("/api/v2/owasps/i", func(w http.ResponseWriter, r *http.Request) {
		testMethod(t, r, "GET")
		fmt.Fprint(w, `{"id":"i"}`)
	})

	me, _, err := client.OWASP.GetByID(context.Background(), "i")
	if err != nil {
		t.Errorf("OWASP.GetByID returned error: %v", err)
	}

	want := &OWASP{ID: "i"}
	if !reflect.DeepEqual(me, want) {
		t.Errorf("OWASP.GetByID returned %+v, want %+v", me, want)
	}
}
