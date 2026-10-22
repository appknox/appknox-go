package helper

import (
	"testing"

	"github.com/stretchr/testify/require"
)

func TestValidateEndpoint(t *testing.T) {
	require.NoError(t, validateEndpoint("http://localhost:8100"))
	require.NoError(t, validateEndpoint("http://127.0.0.1:8100"))
	require.NoError(t, validateEndpoint("https://api.appknox.com"))
	require.Error(t, validateEndpoint("http://api.appknox.com")) // plaintext to remote
	require.Error(t, validateEndpoint("http://192.168.1.10:8100"))
}
