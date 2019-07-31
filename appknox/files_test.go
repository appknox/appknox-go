package appknox

import (
	"context"
	"fmt"
	"net/http"
	"reflect"
	"testing"
)

func TestFilesService_ListByProject(t *testing.T) {
	client, mux, _, teardown := setup()
	defer teardown()

	mux.HandleFunc("/api/projects/1/files", func(w http.ResponseWriter, r *http.Request) {
		testMethod(t, r, "GET")
		fmt.Fprint(w, `{"count": 1, "results":[{"id":1}]}`)
	})

	files, _, err := client.Files.ListByProject(context.Background(), 1, nil)

	if err != nil {
		t.Errorf("Files.ListByProject returned error: %v", err)
	}

	want := []*File{{ID: 1}}
	if !reflect.DeepEqual(files, want) {
		t.Errorf("Files.ListByProject returned %+v, want %+v", files, want)
	}
}

func TestFileResponse_GetNext(t *testing.T) {
	client, mux, _, teardown := setup()
	defer teardown()
	mux.HandleFunc("/api/projects/1/files", func(w http.ResponseWriter, r *http.Request) {
		testMethod(t, r, "GET")
		fmt.Fprint(w, `{"count": 1, "next": "next", "results":[{"id":1}]}`)
	})
	mux.HandleFunc("/next", func(w http.ResponseWriter, r *http.Request) {
		testMethod(t, r, "GET")
		fmt.Fprint(w, `{"count": 1, "results":[{"id":10}]}`)
	})
	_, fileResponse, err := client.Files.ListByProject(context.Background(), 1, nil)
	if err != nil {
		t.Errorf("Files.ListByProject returned error: %v", err)
	}
	files, _, err := fileResponse.GetNext()
	want := []*File{{ID: 10}}
	if !reflect.DeepEqual(files, want) {
		t.Errorf("Files.ListByProject returned %+v, want %+v", files, want)
	}
}

func TestFileResponse_GetPrevious(t *testing.T) {
	client, mux, _, teardown := setup()
	defer teardown()
	mux.HandleFunc("/api/projects/1/files", func(w http.ResponseWriter, r *http.Request) {
		testMethod(t, r, "GET")
		fmt.Fprint(w, `{"count": 1, "previous": "previous", "results":[{"id":10}]}`)
	})
	mux.HandleFunc("/previous", func(w http.ResponseWriter, r *http.Request) {
		testMethod(t, r, "GET")
		fmt.Fprint(w, `{"count": 1, "results":[{"id":1}]}`)
	})
	_, fileResponse, err := client.Files.ListByProject(context.Background(), 1, nil)
	if err != nil {
		t.Errorf("Files.ListByProject returned error: %v", err)
	}
	files, _, err := fileResponse.GetPrevious()
	want := []*File{{ID: 1}}
	if !reflect.DeepEqual(files, want) {
		t.Errorf("Projects.List returned %+v, want %+v", files, want)
	}
}

func TestFilesService_ListByProjectWithOptions(t *testing.T) {
	client, mux, _, teardown := setup()
	defer teardown()

	mux.HandleFunc("/api/projects/1/files", func(w http.ResponseWriter, r *http.Request) {
		testMethod(t, r, "GET")
		testFormValues(t, r, values{
			"version_code": "3",
			"offset":       "1",
			"limit":        "1",
		})
		fmt.Fprint(w,
			`{"count":1, "results":[{"version_code":"3"}]}`)
	})
	options := &FileListOptions{
		VersionCode: *String("3"),
		ListOptions: ListOptions{
			Offset: *Int(1),
			Limit:  *Int(1)},
	}
	files, _, err := client.Files.ListByProject(context.Background(), 1, options)
	if err != nil {
		t.Errorf("Files.ListByProject returned error: %v", err)
	}
	want := []*File{{VersionCode: "3"}}
	if !reflect.DeepEqual(files, want) {
		t.Errorf("Files.ListByProject returned %+v, want %+v", files, want)
	}
}

func TestFilesService_GetByID(t *testing.T) {
	client, mux, _, teardown := setup()
	defer teardown()

	mux.HandleFunc("/api/v2/files/1", func(w http.ResponseWriter, r *http.Request) {
		testMethod(t, r, "GET")
		fmt.Fprint(w, `{"id":1}`)
	})

	me, _, err := client.Files.GetByID(context.Background(), 1)
	if err != nil {
		t.Errorf("Files.GetByID returned error: %v", err)
	}

	want := &File{ID: 1}
	if !reflect.DeepEqual(me, want) {
		t.Errorf("Files.GetByID returned %+v, want %+v", me, want)
	}
}
