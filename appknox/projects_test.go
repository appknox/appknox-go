package appknox

import (
	"context"
	"fmt"
	"net/http"
	"reflect"
	"testing"
)

func TestProjects_marshall(t *testing.T) {
	testJSONMarshal(t, &Project{}, "{}")

	u := &Project{
		ID:          1,
		PackageName: "p",
		Platform:    1,
		FileCount:   1,
	}
	want := `{
		"id": 1,
		"package_name": "p",
		"platform": 1,
		"file_count": 1
	}`
	testJSONMarshal(t, u, want)
}

func TestProjectsService_List(t *testing.T) {
	client, mux, _, teardown := setup()
	defer teardown()
	mux.HandleFunc("/api/me", func(w http.ResponseWriter, r *http.Request) {
		testMethod(t, r, "GET")
		fmt.Fprint(w, `{"default_organization":1}`)
	})
	mux.HandleFunc("/api/organizations/1/projects", func(w http.ResponseWriter, r *http.Request) {
		testMethod(t, r, "GET")
		fmt.Fprint(w, `{"count": 1, "results":[{"id":1}]}`)
	})
	projects, _, err := client.Projects.List(context.Background(), nil)
	if err != nil {
		t.Errorf("Projects.List returned error: %v", err)
	}
	want := []*Project{{ID: 1}}
	if !reflect.DeepEqual(projects, want) {
		t.Errorf("Projects.List returned %+v, want %+v", projects, want)
	}
}

func TestProjectsService_ListWithOptions(t *testing.T) {
	client, mux, _, teardown := setup()
	defer teardown()
	mux.HandleFunc("/api/me", func(w http.ResponseWriter, r *http.Request) {
		testMethod(t, r, "GET")
		fmt.Fprint(w, `{"default_organization":1}`)
	})
	mux.HandleFunc("/api/organizations/1/projects", func(w http.ResponseWriter, r *http.Request) {
		testMethod(t, r, "GET")
		testFormValues(t, r, values{
			"platform":     "0",
			"package_name": "com.appknox.mfva",
			"q":            "com.",
			"offset":       "1",
			"limit":        "1",
		})
		fmt.Fprint(w, `{"count": 1, "results":[{"id":1}]}`)
	})
	options := &ProjectListOptions{
		Platform:    *String("0"),
		PackageName: *String("com.appknox.mfva"),
		Search:      *String("com."),
		ListOptions: ListOptions{
			Offset: *Int(1),
			Limit:  *Int(1)},
	}
	projects, _, err := client.Projects.List(context.Background(), options)
	if err != nil {
		t.Errorf("Projects.List returned error: %v", err)
	}
	want := []*Project{{ID: 1}}
	if !reflect.DeepEqual(projects, want) {
		t.Errorf("Projects.List returned %+v, want %+v", projects, want)
	}
}

func TestProjectResponse_GetNext(t *testing.T) {
	client, mux, _, teardown := setup()
	defer teardown()
	mux.HandleFunc("/api/me", func(w http.ResponseWriter, r *http.Request) {
		testMethod(t, r, "GET")
		fmt.Fprint(w, `{"default_organization":1}`)
	})
	mux.HandleFunc("/api/organizations/1/projects", func(w http.ResponseWriter, r *http.Request) {
		testMethod(t, r, "GET")
		fmt.Fprint(w, `{"count": 1, "next": "next", "results":[{"id":1}]}`)
	})
	mux.HandleFunc("/next", func(w http.ResponseWriter, r *http.Request) {
		testMethod(t, r, "GET")
		fmt.Fprint(w, `{"count": 1, "results":[{"id":10}]}`)
	})
	_, projectResponse, err := client.Projects.List(context.Background(), nil)
	if err != nil {
		t.Errorf("Projects.List returned error: %v", err)
	}
	projects, _, err := projectResponse.GetNext()
	want := []*Project{{ID: 10}}
	if !reflect.DeepEqual(projects, want) {
		t.Errorf("Projects.List returned %+v, want %+v", projects, want)
	}
}

func TestProjectResponse_GetPrevious(t *testing.T) {
	client, mux, _, teardown := setup()
	defer teardown()
	mux.HandleFunc("/api/me", func(w http.ResponseWriter, r *http.Request) {
		testMethod(t, r, "GET")
		fmt.Fprint(w, `{"default_organization":1}`)
	})
	mux.HandleFunc("/api/organizations/1/projects", func(w http.ResponseWriter, r *http.Request) {
		testMethod(t, r, "GET")
		fmt.Fprint(w, `{"count": 1, "previous": "previous", "results":[{"id":10}]}`)
	})
	mux.HandleFunc("/previous", func(w http.ResponseWriter, r *http.Request) {
		testMethod(t, r, "GET")
		fmt.Fprint(w, `{"count": 1, "results":[{"id":1}]}`)
	})
	_, projectResponse, err := client.Projects.List(context.Background(), nil)
	if err != nil {
		t.Errorf("Projects.List returned error: %v", err)
	}
	projects, _, err := projectResponse.GetPrevious()
	want := []*Project{{ID: 1}}
	if !reflect.DeepEqual(projects, want) {
		t.Errorf("Projects.List returned %+v, want %+v", projects, want)
	}
}
