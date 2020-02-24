package helper

import (
	"context"
	"os"

	"github.com/cheynewallace/tabby"
)

// ProcessOwasp takes the me data and print it to CLI.
func ProcessOwasp(owaspID string) {
	ctx := context.Background()
	client := getClient()
	owasp, _, err := client.OWASP.GetByID(ctx, owaspID)
	if err != nil {
		PrintError(err)
		os.Exit(1)
	}
	t := tabby.New()
	t.AddLine("Code: ", owasp.Code)
	t.AddLine("Description: ", owasp.Description)
	t.AddLine("ID: ", owasp.ID)
	t.AddLine("Title: ", owasp.Title)
	t.AddLine("Year: ", owasp.Year)
	t.Print()
}
