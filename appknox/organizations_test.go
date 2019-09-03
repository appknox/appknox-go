package appknox

import (
	"context"
	"fmt"
	"net/http"
	"reflect"
	"testing"
)

func TestOrganziations_marshall(t *testing.T) {
	testJSONMarshal(t, &Organization{}, "{}")
	u := &Organization{
		ID:            1,
		Name:          "n",
		ProjectsCount: 1,
	}
	want := `{
		"id": 1,
		"name": "n",
		"projects_count": 1
	}`
	testJSONMarshal(t, u, want)
}

func TestOrganizationsService_List(t *testing.T) {
	client, mux, _, teardown := setup()
	defer teardown()

	mux.HandleFunc("/api/organizations", func(w http.ResponseWriter, r *http.Request) {
		testMethod(t, r, "GET")
		fmt.Fprint(w, `{"count": 1, "results":[{"id":1}]}`)
	})

	organizations, _, err := client.Organizations.List(context.Background())

	if err != nil {
		t.Errorf("Organizations.List returned error: %v", err)
	}

	want := []*Organization{{ID: 1}}
	if !reflect.DeepEqual(organizations, want) {
		t.Errorf("Organizations.List returned %+v, want %+v", organizations, want)
	}
}
