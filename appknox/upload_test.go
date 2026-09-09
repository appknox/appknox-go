package appknox

import (
	"context"
	"fmt"
	"net/http"
	"os"
	"reflect"
	"strconv"
	"testing"
)

func TestUpload_marshall(t *testing.T) {
	testJSONMarshal(t, &Upload{}, "{}")

	u := &Upload{
		URL:           "u",
		FileKey:       "f",
		FileKeySigned: "fks",
		SubmissionID:  1,
		KnoxIQ:        true,
	}
	want := `{
		"url": "u",
		"file_key": "f",
		"file_key_signed": "fks",
		"submission_id": 1,
		"knoxiq": true
	}`
	testJSONMarshal(t, u, want)
}

func TestUploadService_CheckSubmission(t *testing.T) {
	client, mux, _, teardown := setup()
	defer teardown()

	mux.HandleFunc("/api/submissions/1", func(w http.ResponseWriter, r *http.Request) {
		testMethod(t, r, "GET")
		fmt.Fprint(w, `{"id":1, "file":2}`)
	})
	mux.HandleFunc("/api/v2/files/2", func(w http.ResponseWriter, r *http.Request) {
		testMethod(t, r, "GET")
		fmt.Fprint(w, `{"id":2}`)
	})
	akFile, _, err := client.Upload.CheckSubmission(context.Background(), 1)
	if err != nil {
		t.Errorf("Upload.CheckSubmission returned error: %v", err)
	}

	want := &File{ID: 2}
	if !reflect.DeepEqual(akFile, want) {
		t.Errorf("Upload.CheckSubmission returned %+v, want %+v", akFile, want)
	}
}

func TestUploadService_uploadFileUsingReaderHelper(t *testing.T) {
	client, mux, _, teardown := setup()
	defer teardown()

	mux.HandleFunc("/api/me", func(w http.ResponseWriter, r *http.Request) {
		testMethod(t, r, "GET")
		fmt.Fprint(w, `{"default_organization":1}`)
	})
	mux.HandleFunc("/api/organizations/1/upload_app", func(w http.ResponseWriter, r *http.Request) {
		testMethod(t, r, "GET")
		fmt.Fprint(w, `{"url":"u"}`)
	})

	me, _, err := client.Me.CurrentAuthenticatedUser(context.Background())
	orgID := strconv.Itoa(me.DefaultOrganization)
	u := fmt.Sprintf("api/organizations/%s/upload_app", orgID)

	file, dir, err := openTestFile("upload.txt", "Upload me !\n")
	if err != nil {
		t.Fatalf("Unable to create temp file: %v", err)
	}
	defer os.RemoveAll(dir)

	mux.HandleFunc("/u", func(w http.ResponseWriter, r *http.Request) {
		testMethod(t, r, "PUT")
		testBody(t, r, "Upload me !\n")
	})

	upload, err := client.Upload.uploadFileUsingReaderHelper(context.Background(), file, 12, u)
	if err != nil {
		t.Errorf("Upload.uploadFileUsingReader returned error: %v", err)
	}

	want := &Upload{URL: "u"}
	if !reflect.DeepEqual(upload, want) {
		t.Errorf("Upload.uploadFileUsingReader returned %+v, want %+v", upload, want)
	}
}

func TestUploadService_UploadFileUsingReader(t *testing.T) {
	client, mux, _, teardown := setup()
	defer teardown()

	mux.HandleFunc("/api/me", func(w http.ResponseWriter, r *http.Request) {
		testMethod(t, r, "GET")
		fmt.Fprint(w, `{"default_organization":1}`)
	})
	mux.HandleFunc("/api/organizations/1/upload_app", func(w http.ResponseWriter, r *http.Request) {
		if r.Method == "GET" {
			testMethod(t, r, "GET")
			fmt.Fprint(w, `{"url":"u"}`)
		} else {
			testMethod(t, r, "POST")
			testBody(t, r, `{"url":"u"}`+"\n")
			fmt.Fprint(w, `{"submission_id":1}`)
		}
	})

	file, dir, err := openTestFile("upload.txt", "Upload me !\n")
	if err != nil {
		t.Fatalf("Unable to create temp file: %v", err)
	}
	defer os.RemoveAll(dir)

	mux.HandleFunc("/u", func(w http.ResponseWriter, r *http.Request) {
		testMethod(t, r, "PUT")
		testBody(t, r, "Upload me !\n")
	})

	submissionID, err := client.Upload.UploadFileUsingReader(context.Background(), file, 12, false)
	if err != nil {
		t.Errorf("Upload.UploadFileUsingReader returned error: %v", err)
	}

	want := 1
	if !reflect.DeepEqual(*submissionID, want) {
		t.Errorf("Upload.UploadFileUsingReader returned %+v, want %+v", *submissionID, want)
	}
}

// TestUploadService_UploadFileUsingReader_KnoxIQFlag verifies the knoxiq flag
// is marshalled into the POST body (the omitted-when-false case is already
// covered by TestUploadService_UploadFileUsingReader's body assertion).
func TestUploadService_UploadFileUsingReader_KnoxIQFlag(t *testing.T) {
	client, mux, _, teardown := setup()
	defer teardown()

	mux.HandleFunc("/api/me", func(w http.ResponseWriter, r *http.Request) {
		testMethod(t, r, "GET")
		fmt.Fprint(w, `{"default_organization":1}`)
	})
	mux.HandleFunc("/api/organizations/1/upload_app", func(w http.ResponseWriter, r *http.Request) {
		if r.Method == "GET" {
			testMethod(t, r, "GET")
			fmt.Fprint(w, `{"url":"u"}`)
		} else {
			testMethod(t, r, "POST")
			testBody(t, r, `{"url":"u","knoxiq":true}`+"\n")
			fmt.Fprint(w, `{"submission_id":1}`)
		}
	})

	file, dir, err := openTestFile("upload.txt", "Upload me !\n")
	if err != nil {
		t.Fatalf("Unable to create temp file: %v", err)
	}
	defer os.RemoveAll(dir)

	mux.HandleFunc("/u", func(w http.ResponseWriter, r *http.Request) {
		testMethod(t, r, "PUT")
		testBody(t, r, "Upload me !\n")
	})

	submissionID, err := client.Upload.UploadFileUsingReader(context.Background(), file, 12, true)
	if err != nil {
		t.Fatalf("Upload.UploadFileUsingReader returned error: %v", err)
	}
	if *submissionID != 1 {
		t.Errorf("Upload.UploadFileUsingReader returned %d, want 1", *submissionID)
	}
}

func TestUploadService_UploadFile(t *testing.T) {
	client, mux, _, teardown := setup()
	defer teardown()

	mux.HandleFunc("/api/me", func(w http.ResponseWriter, r *http.Request) {
		testMethod(t, r, "GET")
		fmt.Fprint(w, `{"default_organization":1}`)
	})
	mux.HandleFunc("/api/submissions/1", func(w http.ResponseWriter, r *http.Request) {
		testMethod(t, r, "GET")
		fmt.Fprint(w, `{"id":1, "file":2}`)
	})
	mux.HandleFunc("/api/v2/files/2", func(w http.ResponseWriter, r *http.Request) {
		testMethod(t, r, "GET")
		fmt.Fprint(w, `{"id":2}`)
	})
	mux.HandleFunc("/api/organizations/1/upload_app", func(w http.ResponseWriter, r *http.Request) {
		if r.Method == "GET" {
			testMethod(t, r, "GET")
			fmt.Fprint(w, `{"url":"u"}`)
		} else {
			testMethod(t, r, "POST")
			testBody(t, r, `{"url":"u"}`+"\n")
			fmt.Fprint(w, `{"submission_id":1}`)
		}
	})

	file, dir, err := openTestFile("upload.txt", "Upload me !\n")
	if err != nil {
		t.Fatalf("Unable to create temp file: %v", err)
	}
	defer os.RemoveAll(dir)

	mux.HandleFunc("/u", func(w http.ResponseWriter, r *http.Request) {
		testMethod(t, r, "PUT")
		testBody(t, r, "Upload me !\n")
	})

	akFile, _, err := client.Upload.UploadFile(context.Background(), file, false)
	if err != nil {
		t.Errorf("Upload.UploadFile returned error: %v", err)
	}

	want := &File{ID: 2}
	if !reflect.DeepEqual(akFile, want) {
		t.Errorf("Upload.UploadFile returned %+v, want %+v", akFile, want)
	}
}
