package appknox

import (
	"context"
	"fmt"
	"net/http"
	"reflect"
	"testing"
)

func TestUser_marshall(t *testing.T) {
	testJSONMarshal(t, &Me{}, "{}")

	u := &Me{
		ID:                  1,
		Username:            "u",
		Email:               "e",
		DefaultOrganization: 1,
	}
	want := `{
		"id": 1,
		"username": "u",
		"email": "e",
		"default_organization": 1
	}`
	testJSONMarshal(t, u, want)
}

func TestMeService_CurrentAuthenticatedUser(t *testing.T) {
	client, mux, _, teardown := setup()
	defer teardown()

	mux.HandleFunc("/api/me", func(w http.ResponseWriter, r *http.Request) {
		testMethod(t, r, "GET")
		fmt.Fprint(w, `{"id":1}`)
	})

	me, _, err := client.Me.CurrentAuthenticatedUser(context.Background())
	if err != nil {
		t.Errorf("Me.CurrentAuthenticatedUser returned error: %v", err)
	}

	want := &Me{ID: 1}
	if !reflect.DeepEqual(me, want) {
		t.Errorf("Me.CurrentAuthenticatedUser returned %+v, want %+v", me, want)
	}
}
