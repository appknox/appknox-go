package helper

import (
	"errors"
	"strconv"
	"strings"
)

// errNoFileID is returned when neither --file-id nor APPKNOX_FILE_ID is set.
// `appknox upload` only prints the id, so the pipeline must pass it on.
var errNoFileID = errors.New("No file id found. Pass --file-id or set APPKNOX_FILE_ID")

// resolveKnoxFixerFileID: --file-id flag > APPKNOX_FILE_ID env > error.
func resolveKnoxFixerFileID(flagValue int, getenv func(string) string) (int, error) {
	if flagValue > 0 {
		return flagValue, nil
	}
	raw := strings.TrimSpace(getenv("APPKNOX_FILE_ID"))
	if raw == "" {
		return 0, errNoFileID
	}
	id, err := strconv.Atoi(raw)
	if err != nil || id <= 0 {
		return 0, errors.New("APPKNOX_FILE_ID must be a positive integer file id")
	}
	return id, nil
}
