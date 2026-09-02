package helper

import (
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/spf13/viper"
	"github.com/stretchr/testify/assert"
)

// TestScheduleDastAutomation_400 checks a 400 response => "request failed: POST ...: 400"
func TestScheduleDastAutomation_400(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == "/api/v2/files/123/dynamicscans" && r.Method == http.MethodPost {
			w.WriteHeader(http.StatusBadRequest) // 400
		} else {
			http.NotFound(w, r)
		}
	}))
	defer server.Close()

	oldToken := viper.GetString("access-token")
	oldHost := viper.GetString("host")
	viper.Set("access-token", "FAKE-TOKEN")
	viper.Set("host", server.URL+"/")
	defer func() {
		viper.Set("access-token", oldToken)
		viper.Set("host", oldHost)
	}()

	err := ScheduleDastAutomation(123)
	assert.Error(t, err)
	assert.Contains(t, err.Error(), "request failed: POST")
	assert.Contains(t, err.Error(), "/api/v2/files/123/dynamicscans: 400")
}

// TestScheduleDastAutomation_403 checks a 403 response => "request failed: POST ...: 403"
func TestScheduleDastAutomation_403(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == "/api/v2/files/999/dynamicscans" && r.Method == http.MethodPost {
			w.WriteHeader(http.StatusForbidden) // 403
		} else {
			http.NotFound(w, r)
		}
	}))
	defer server.Close()

	oldToken := viper.GetString("access-token")
	oldHost := viper.GetString("host")
	viper.Set("access-token", "FAKE-TOKEN")
	viper.Set("host", server.URL+"/")
	defer func() {
		viper.Set("access-token", oldToken)
		viper.Set("host", oldHost)
	}()

	err := ScheduleDastAutomation(999)
	assert.Error(t, err)
	assert.Contains(t, err.Error(), "request failed: POST")
	assert.Contains(t, err.Error(), "/api/v2/files/999/dynamicscans: 403")
}

// TestScheduleDastAutomation_201 => success => no error
func TestScheduleDastAutomation_201(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == "/api/v2/files/555/dynamicscans" && r.Method == http.MethodPost {
			w.WriteHeader(http.StatusCreated) // 201
		} else {
			http.NotFound(w, r)
		}
	}))
	defer server.Close()

	oldToken := viper.GetString("access-token")
	oldHost := viper.GetString("host")
	viper.Set("access-token", "FAKE-TOKEN")
	viper.Set("host", server.URL+"/")
	defer func() {
		viper.Set("access-token", oldToken)
		viper.Set("host", oldHost)
	}()

	err := ScheduleDastAutomation(555)
	assert.NoError(t, err)
}

// TestScheduleDastAutomation_500 => "request failed: POST ...: 500"
func TestScheduleDastAutomation_500(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == "/api/v2/files/9999/dynamicscans" && r.Method == http.MethodPost {
			w.WriteHeader(http.StatusInternalServerError) // 500
		} else {
			http.NotFound(w, r)
		}
	}))
	defer server.Close()

	oldToken := viper.GetString("access-token")
	oldHost := viper.GetString("host")
	viper.Set("access-token", "FAKE-TOKEN")
	viper.Set("host", server.URL+"/")
	defer func() {
		viper.Set("access-token", oldToken)
		viper.Set("host", oldHost)
	}()

	err := ScheduleDastAutomation(9999)
	assert.Error(t, err)
	assert.Contains(t, err.Error(), "request failed: POST")
	assert.Contains(t, err.Error(), "/api/v2/files/9999/dynamicscans: 500")
}
