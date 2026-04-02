package helper

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"os"
	"os/exec"
	"os/signal"
	"syscall"
	"time"
)

const iosAgentVersion = "1.0.0"
const maxRequestBodySize = 1 << 20 // 1 MB

type deviceIDRequest struct {
	ID string `json:"id"`
}

type installRequest struct {
	ID   string `json:"id"`
	Path string `json:"path"`
}

type uninstallRequest struct {
	ID       string `json:"id"`
	BundleID string `json:"bundleId"`
}

func corsMiddleware(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Access-Control-Allow-Origin", "*")
		w.Header().Set("Access-Control-Allow-Methods", "GET, POST, OPTIONS")
		w.Header().Set("Access-Control-Allow-Headers", "Content-Type")

		if r.Method == http.MethodOptions {
			w.WriteHeader(http.StatusNoContent)
			return
		}
		next.ServeHTTP(w, r)
	})
}

func maxBytesMiddleware(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Body != nil {
			r.Body = http.MaxBytesReader(w, r.Body, maxRequestBodySize)
		}
		next.ServeHTTP(w, r)
	})
}

func writeJSON(w http.ResponseWriter, status int, v any) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	json.NewEncoder(w).Encode(v)
}

func writeError(w http.ResponseWriter, status int, msg string) {
	writeJSON(w, status, map[string]string{"message": msg})
}

func isToolNotFound(err error) bool {
	var execErr *exec.Error
	return errors.As(err, &execErr) && errors.Is(execErr.Err, exec.ErrNotFound)
}

func toolNotFoundMsg(tool string) string {
	return fmt.Sprintf("%s not found. Install prerequisites:\n  brew install libimobiledevice ideviceinstaller", tool)
}

func handleHealth(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		writeError(w, http.StatusMethodNotAllowed, "method not allowed")
		return
	}
	writeJSON(w, http.StatusOK, map[string]string{
		"status":  "ok",
		"version": iosAgentVersion,
	})
}

func handleDetect(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		writeError(w, http.StatusMethodNotAllowed, "method not allowed")
		return
	}
	ids, err := DetectDevice()
	if err != nil {
		if isToolNotFound(err) {
			writeError(w, http.StatusServiceUnavailable, toolNotFoundMsg("idevice_id"))
			return
		}
		writeError(w, http.StatusBadRequest, err.Error())
		return
	}
	if len(ids) == 0 {
		writeJSON(w, http.StatusOK, map[string]any{"device": nil})
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{
		"device": map[string]string{
			"platform": "ios",
			"id":       ids[0],
		},
	})
}

func handlePair(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		writeError(w, http.StatusMethodNotAllowed, "method not allowed")
		return
	}
	var req deviceIDRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		writeError(w, http.StatusBadRequest, "invalid request body")
		return
	}
	if !validateDeviceID(req.ID) {
		writeError(w, http.StatusBadRequest, "invalid device ID")
		return
	}
	err := PairDevice(req.ID)
	if err != nil {
		if isToolNotFound(err) {
			writeError(w, http.StatusServiceUnavailable, toolNotFoundMsg("idevicepair"))
			return
		}
		writeError(w, http.StatusBadRequest, err.Error())
		return
	}
	writeJSON(w, http.StatusOK, map[string]bool{"success": true})
}

func handleFetch(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		writeError(w, http.StatusMethodNotAllowed, "method not allowed")
		return
	}
	var req deviceIDRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		writeError(w, http.StatusBadRequest, "invalid request body")
		return
	}
	if !validateDeviceID(req.ID) {
		writeError(w, http.StatusBadRequest, "invalid device ID")
		return
	}
	info, err := FetchDeviceInfo(req.ID)
	if err != nil {
		if isToolNotFound(err) {
			writeError(w, http.StatusServiceUnavailable, toolNotFoundMsg("ideviceinfo"))
			return
		}
		writeError(w, http.StatusBadRequest, err.Error())
		return
	}
	writeJSON(w, http.StatusOK, info)
}

func handleInstall(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		writeError(w, http.StatusMethodNotAllowed, "method not allowed")
		return
	}
	var req installRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		writeError(w, http.StatusBadRequest, "invalid request body")
		return
	}
	if !validateDeviceID(req.ID) {
		writeError(w, http.StatusBadRequest, "invalid device ID")
		return
	}
	if err := validateIPAPath(req.Path); err != nil {
		writeError(w, http.StatusBadRequest, err.Error())
		return
	}
	err := InstallApp(req.ID, req.Path)
	if err != nil {
		if isToolNotFound(err) {
			writeError(w, http.StatusServiceUnavailable, toolNotFoundMsg("ideviceinstaller"))
			return
		}
		writeError(w, http.StatusBadRequest, err.Error())
		return
	}
	writeJSON(w, http.StatusOK, map[string]bool{"success": true})
}

func handleUninstall(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		writeError(w, http.StatusMethodNotAllowed, "method not allowed")
		return
	}
	var req uninstallRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		writeError(w, http.StatusBadRequest, "invalid request body")
		return
	}
	if !validateDeviceID(req.ID) {
		writeError(w, http.StatusBadRequest, "invalid device ID")
		return
	}
	if !validateBundleID(req.BundleID) {
		writeError(w, http.StatusBadRequest, "invalid bundle ID")
		return
	}
	err := UninstallApp(req.ID, req.BundleID)
	if err != nil {
		if isToolNotFound(err) {
			writeError(w, http.StatusServiceUnavailable, toolNotFoundMsg("ideviceinstaller"))
			return
		}
		writeError(w, http.StatusBadRequest, err.Error())
		return
	}
	writeJSON(w, http.StatusOK, map[string]bool{"success": true})
}

func handleApps(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		writeError(w, http.StatusMethodNotAllowed, "method not allowed")
		return
	}
	var req deviceIDRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		writeError(w, http.StatusBadRequest, "invalid request body")
		return
	}
	if !validateDeviceID(req.ID) {
		writeError(w, http.StatusBadRequest, "invalid device ID")
		return
	}
	apps, err := ListApps(req.ID)
	if err != nil {
		if isToolNotFound(err) {
			writeError(w, http.StatusServiceUnavailable, toolNotFoundMsg("ideviceinstaller"))
			return
		}
		writeError(w, http.StatusBadRequest, err.Error())
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{"apps": apps})
}

// newIOSAgentMux creates the HTTP mux with all routes, CORS, and body size limit middleware.
func newIOSAgentMux() http.Handler {
	mux := http.NewServeMux()
	mux.HandleFunc("/health", handleHealth)
	mux.HandleFunc("/detect", handleDetect)
	mux.HandleFunc("/pair", handlePair)
	mux.HandleFunc("/fetch", handleFetch)
	mux.HandleFunc("/install", handleInstall)
	mux.HandleFunc("/uninstall", handleUninstall)
	mux.HandleFunc("/apps", handleApps)
	return corsMiddleware(maxBytesMiddleware(mux))
}

// StartIOSAgent starts the iOS agent HTTP server on the given port.
// It blocks until interrupted (Ctrl+C / SIGTERM).
func StartIOSAgent(port int) {
	if port < 1 || port > 65535 {
		PrintError(fmt.Sprintf("invalid port: %d (must be 1-65535)", port))
		os.Exit(1)
	}

	addr := fmt.Sprintf("localhost:%d", port)
	handler := newIOSAgentMux()

	fmt.Printf("KnoxOps iOS Agent running on http://%s\n", addr)
	fmt.Println("Waiting for iOS device connections...")
	fmt.Println()
	fmt.Println("Prerequisites:")
	fmt.Println("  brew install libimobiledevice ideviceinstaller")

	server := &http.Server{
		Addr:    addr,
		Handler: handler,
	}

	go func() {
		sigCh := make(chan os.Signal, 1)
		signal.Notify(sigCh, syscall.SIGINT, syscall.SIGTERM)
		<-sigCh
		fmt.Println("\nShutting down iOS Agent...")
		ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
		defer cancel()
		server.Shutdown(ctx)
	}()

	if err := server.ListenAndServe(); err != nil && err != http.ErrServerClosed {
		PrintError(fmt.Sprintf("Failed to start server: %s", err))
		os.Exit(1)
	}
}
