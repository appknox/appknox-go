package helper

import (
	"context"
	"os"

	"github.com/appknox/appknox-go/appknox"
	"github.com/cheynewallace/tabby"
)

// MeData represents a struct which will be printed to the CLI.
type MeData struct {
	ID                  int    `header:"id"`
	Username            string `header:"username"`
	Email               string `header:"email"`
	DefaultOrganization int    `header:"default-organization"`
}

// ProcessMe takes the me data and print it to CLI.
func ProcessMe() {
	me, err := GetMe()
	if err != nil {
		PrintError(err)
		os.Exit(1)
	}
	t := tabby.New()
	t.AddLine("ID: ", me.ID)
	t.AddLine("Username: ", me.Username)
	t.AddLine("Email: ", me.Email)
	t.Print()
}

// GetMe return current User.
func GetMe() (*appknox.Me, error) {
	ctx := context.Background()
	client := getClient()
	me, _, err := client.Me.CurrentAuthenticatedUser(ctx)
	return me, err
}
