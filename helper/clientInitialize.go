package helper

import (
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

// GetHostMappings returns a map of host names to URLs.
func GetHostMappings() map[string]string {
	return map[string]string{
		"global": "https://api.appknox.com/",
		"saudi":  "https://sa.secure.appknox.com/",
		// Add more mappings as needed
	}
}

// ResolveHostAndRegion checks the host and region and returns the resolved base URL
func ResolveHostAndRegion(host, region string, hostMappings map[string]string) (string, error) {
	// If both region and host are provided, prioritize host and ignore region
	if host != "" {
		// Validate the host is a proper URL
		_, err := url.ParseRequestURI(host)
		if err != nil {
			return "", fmt.Errorf("invalid host URL: %s", host)
		}
		return host, nil
	}

	// If region is provided, map it to the host URL
	if region != "" {
		if mappedHost, exists := hostMappings[region]; exists {
			return mappedHost, nil
		}
		// Invalid region, return error and show available regions
		availableRegions := make([]string, 0, len(hostMappings))
		for key := range hostMappings {
			availableRegions = append(availableRegions, key)
		}
		return "", fmt.Errorf("Invalid region name: %s. Available regions: %s", region, strings.Join(availableRegions, ", "))
	}

	// If neither host nor region are provided, default to the global host
	return hostMappings["global"], nil
}

func getClient() *appknox.Client {
	token := getAppknoxAccessToken()

	// Check for region and host first
	region := viper.GetString("region")
	host := viper.GetString("host")

	// Get the host mappings
	hostMappings := GetHostMappings()

	// Use the new function to resolve the host and region
	resolvedHost, err := ResolveHostAndRegion(host, region, hostMappings)
	if err != nil {
		fmt.Println(err)
		os.Exit(1)
	}

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

	baseHost, err := url.Parse(resolvedHost)
	if err != nil {
		fmt.Println(err)
		os.Exit(1)
	}
	client.BaseURL = baseHost
	return client
}

// CheckToken checks if access token is valid.
func CheckToken() (*appknox.Me, error) {
	return GetMe()
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
