package helper

import (
	"bytes"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/stretchr/testify/assert"
)

func TestHealthHandler(t *testing.T) {
	handler := newIOSAgentMux()
	req := httptest.NewRequest(http.MethodGet, "/health", nil)
	w := httptest.NewRecorder()

	handler.ServeHTTP(w, req)

	assert.Equal(t, http.StatusOK, w.Code)

	var resp map[string]string
	json.Unmarshal(w.Body.Bytes(), &resp)
	assert.Equal(t, "ok", resp["status"])
	assert.NotEmpty(t, resp["version"])
}

func TestDetectHandlerWrongMethod(t *testing.T) {
	handler := newIOSAgentMux()
	req := httptest.NewRequest(http.MethodGet, "/detect", nil)
	w := httptest.NewRecorder()

	handler.ServeHTTP(w, req)

	assert.Equal(t, http.StatusMethodNotAllowed, w.Code)
}

func TestPairHandlerInvalidID(t *testing.T) {
	handler := newIOSAgentMux()
	body, _ := json.Marshal(map[string]string{"id": "id;rm -rf /"})
	req := httptest.NewRequest(http.MethodPost, "/pair", bytes.NewReader(body))
	req.Header.Set("Content-Type", "application/json")
	w := httptest.NewRecorder()

	handler.ServeHTTP(w, req)

	assert.Equal(t, http.StatusBadRequest, w.Code)
}

func TestPairHandlerMissingID(t *testing.T) {
	handler := newIOSAgentMux()
	body, _ := json.Marshal(map[string]string{})
	req := httptest.NewRequest(http.MethodPost, "/pair", bytes.NewReader(body))
	req.Header.Set("Content-Type", "application/json")
	w := httptest.NewRecorder()

	handler.ServeHTTP(w, req)

	assert.Equal(t, http.StatusBadRequest, w.Code)
}

func TestFetchHandlerInvalidID(t *testing.T) {
	handler := newIOSAgentMux()
	body, _ := json.Marshal(map[string]string{"id": ""})
	req := httptest.NewRequest(http.MethodPost, "/fetch", bytes.NewReader(body))
	req.Header.Set("Content-Type", "application/json")
	w := httptest.NewRecorder()

	handler.ServeHTTP(w, req)

	assert.Equal(t, http.StatusBadRequest, w.Code)
}

func TestInstallHandlerMissingPath(t *testing.T) {
	handler := newIOSAgentMux()
	body, _ := json.Marshal(map[string]string{"id": "abc123"})
	req := httptest.NewRequest(http.MethodPost, "/install", bytes.NewReader(body))
	req.Header.Set("Content-Type", "application/json")
	w := httptest.NewRecorder()

	handler.ServeHTTP(w, req)

	assert.Equal(t, http.StatusBadRequest, w.Code)
}

func TestInstallHandlerNonIPA(t *testing.T) {
	handler := newIOSAgentMux()
	body, _ := json.Marshal(map[string]string{"id": "abc123", "path": "/tmp/app.apk"})
	req := httptest.NewRequest(http.MethodPost, "/install", bytes.NewReader(body))
	req.Header.Set("Content-Type", "application/json")
	w := httptest.NewRecorder()

	handler.ServeHTTP(w, req)

	assert.Equal(t, http.StatusBadRequest, w.Code)
}

func TestUninstallHandlerMissingBundleID(t *testing.T) {
	handler := newIOSAgentMux()
	body, _ := json.Marshal(map[string]string{"id": "abc123"})
	req := httptest.NewRequest(http.MethodPost, "/uninstall", bytes.NewReader(body))
	req.Header.Set("Content-Type", "application/json")
	w := httptest.NewRecorder()

	handler.ServeHTTP(w, req)

	assert.Equal(t, http.StatusBadRequest, w.Code)
}

func TestUninstallHandlerInvalidBundleID(t *testing.T) {
	handler := newIOSAgentMux()
	body, _ := json.Marshal(map[string]string{"id": "abc123", "bundleId": "com.bad;inject"})
	req := httptest.NewRequest(http.MethodPost, "/uninstall", bytes.NewReader(body))
	req.Header.Set("Content-Type", "application/json")
	w := httptest.NewRecorder()

	handler.ServeHTTP(w, req)

	assert.Equal(t, http.StatusBadRequest, w.Code)
}

func TestAppsHandlerInvalidID(t *testing.T) {
	handler := newIOSAgentMux()
	body, _ := json.Marshal(map[string]string{"id": "bad id!"})
	req := httptest.NewRequest(http.MethodPost, "/apps", bytes.NewReader(body))
	req.Header.Set("Content-Type", "application/json")
	w := httptest.NewRecorder()

	handler.ServeHTTP(w, req)

	assert.Equal(t, http.StatusBadRequest, w.Code)
}

func TestCORSHeaders(t *testing.T) {
	handler := newIOSAgentMux()
	req := httptest.NewRequest(http.MethodOptions, "/health", nil)
	req.Header.Set("Origin", "http://localhost:3000")
	req.Header.Set("Access-Control-Request-Method", "POST")
	w := httptest.NewRecorder()

	handler.ServeHTTP(w, req)

	assert.Equal(t, "*", w.Header().Get("Access-Control-Allow-Origin"))
	assert.Equal(t, http.StatusNoContent, w.Code)
}

func TestCORSHeadersOnRegularRequest(t *testing.T) {
	handler := newIOSAgentMux()
	req := httptest.NewRequest(http.MethodGet, "/health", nil)
	req.Header.Set("Origin", "http://localhost:3000")
	w := httptest.NewRecorder()

	handler.ServeHTTP(w, req)

	assert.Equal(t, "*", w.Header().Get("Access-Control-Allow-Origin"))
	assert.Equal(t, http.StatusOK, w.Code)
}
