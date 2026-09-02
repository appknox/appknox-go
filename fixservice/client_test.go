package fixservice

import (
	"testing"

	"github.com/stretchr/testify/require"
)

func TestValidateEndpoint(t *testing.T) {
	require.NoError(t, ValidateEndpoint("http://localhost:8100"))
	require.NoError(t, ValidateEndpoint("http://127.0.0.1:8100"))
	require.NoError(t, ValidateEndpoint("https://fix.appknox.com"))
	require.Error(t, ValidateEndpoint("http://fix.appknox.com")) // plaintext to remote
	require.Error(t, ValidateEndpoint("http://192.168.1.10:8100"))
}
