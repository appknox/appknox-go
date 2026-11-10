package agent

import (
	"testing"

	sdk "github.com/anthropics/anthropic-sdk-go"
	"github.com/stretchr/testify/require"
)

func TestExtractText_JoinsTextBlocks(t *testing.T) {
	msg := &sdk.BetaMessage{Content: []sdk.BetaContentBlockUnion{
		{Type: "text", Text: "app/A.java"},
		{Type: "tool_use"},
	}}
	require.Equal(t, "app/A.java\n", extractText(msg))
}

func TestExtractText_NilMessage(t *testing.T) {
	require.Equal(t, "", extractText(nil))
}
