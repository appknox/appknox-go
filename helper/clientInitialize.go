package helper

import (
	"context"
	"fmt"
	"log"
	"net/url"
	"os"
	"strings"

	"github.com/appknox/appknox-go/appknox"
	"github.com/jackwakefield/gopac"
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
	proxyURL, err := GetProxy()
	if err != nil {
		fmt.Println(err)
		os.Exit(1)
	}
	insecure := viper.GetBool("insecure")
	client = client.SetHTTPTransportParams(proxyURL, insecure)
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

// GetProxy return the proxy url if proxy is set.
func GetProxy() (*url.URL, error) {
	host := viper.GetString("host")
	pac := viper.GetString("pac")
	if pac == "" {
		proxy := viper.GetString("proxy")
		if proxy == "" {
			return nil, nil
		}
		proxyURL, errParse := url.Parse(proxy)
		if errParse != nil {
			return nil, errParse
		}
		return proxyURL, nil
	}
	parser := new(gopac.Parser)
	if err := parser.ParseUrl(pac); err != nil {
		log.Fatalf("Failed to parse PAC (%s)", err)
	}
	result, errResult := parser.FindProxy("", host)

	if errResult != nil {
		return nil, errResult
	}

	if strings.Contains(result, "DIRECT") {
		return nil, nil
	}

	var urlProxy string

	host = strings.Replace(result, "PROXY ", "", -1)
	urlProxy = "http://" + host

	proxyURL, errParse := url.Parse(urlProxy)
	if errParse != nil {
		return nil, errResult
	}
	return proxyURL, nil
}
