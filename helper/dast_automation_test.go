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
        if r.URL.Path == "/api/dynamicscan/123/schedule_automation" && r.Method == http.MethodPost {
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
    errStr := err.Error()
    assert.Contains(t, errStr, "request failed: POST ")
    assert.Contains(t, errStr, "/api/dynamicscan/123/schedule_automation: 400")
}

// TestScheduleDastAutomation_403 checks a 403 response => "request failed: POST ...: 403"
func TestScheduleDastAutomation_403(t *testing.T) {
    server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
        if r.URL.Path == "/api/dynamicscan/999/schedule_automation" && r.Method == http.MethodPost {
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
    errStr := err.Error()
    assert.Contains(t, errStr, "request failed: POST ")
    assert.Contains(t, errStr, "/api/dynamicscan/999/schedule_automation: 403")
}

// TestScheduleDastAutomation_204 => success => no error
func TestScheduleDastAutomation_204(t *testing.T) {
    server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
        if r.URL.Path == "/api/dynamicscan/555/schedule_automation" && r.Method == http.MethodPost {
            w.WriteHeader(http.StatusNoContent) // 204
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
        if r.URL.Path == "/api/dynamicscan/9999/schedule_automation" && r.Method == http.MethodPost {
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
    errStr := err.Error()
    assert.Contains(t, errStr, "request failed: POST ")
    assert.Contains(t, errStr, "/api/dynamicscan/9999/schedule_automation: 500")
}
