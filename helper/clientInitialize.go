package helper

import (
	"context"
	"fmt"
	"net/url"
	"os"

	"github.com/appknox/appknox-go/appknox"
	"github.com/spf13/viper"
)

func getAppknoxAccessToken() string {
	accessToken := viper.GetString("access-token")
	if accessToken == "" {
		fmt.Println("Appknox access token missing!")
		fmt.Println("Please run 'appknox init' to set the token.")
		fmt.Println("Or in case you're integrating appknox on a CI/CD tool")
		fmt.Println("Use APPKNOX_ACCESS_TOKEN as env.")
		os.Exit(1)
	}
	_, err := CheckToken()
	if err != nil {
		fmt.Println(err)
		os.Exit(1)
	}
	return accessToken
}

func getClient() *appknox.Client {
	token := getAppknoxAccessToken()
	host := viper.GetString("host")
	client, err := appknox.NewClient(token)
	if err != nil {
		fmt.Println(err)
		os.Exit(1)
	}
	baseHost, err := url.Parse(host)
	if err != nil {
		fmt.Println(err)
		os.Exit(1)
	}
	client.BaseURL = baseHost
	return client
}

// CheckToken checks if access token is valid.
func CheckToken() (*appknox.Me, error) {
	accessToken := viper.GetString("access-token")
	host := viper.GetString("host")
	baseHost, err := url.Parse(host)
	if err != nil {
		fmt.Println(err)
		os.Exit(1)
	}
	ctx := context.Background()
	client, err := appknox.NewClient(accessToken)
	if err != nil {
		return nil, err
	}
	client.BaseURL = baseHost
	me, _, err := client.Me.CurrentAuthenticatedUser(ctx)
	return me, err
}
