package agent

import (
	"strings"

	sdk "github.com/anthropics/anthropic-sdk-go"
)

// extractText concatenates the text blocks of a model message.
func extractText(msg *sdk.BetaMessage) string {
	if msg == nil {
		return ""
	}
	var b strings.Builder
	for _, block := range msg.Content {
		if block.Type == "text" && block.Text != "" {
			b.WriteString(block.Text)
			b.WriteByte('\n')
		}
	}
	return b.String()
}
