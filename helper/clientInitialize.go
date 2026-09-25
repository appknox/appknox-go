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
	"sort"
)

// credentials holds exactly one resolved credential type: either a Personal
// Access Token, or a service account access key ID / secret pair.
type credentials struct {
	accessToken     string
	accessKeyID     string
	accessKeySecret string
}

func (c credentials) isServiceAccount() bool {
	return c.accessKeyID != "" || c.accessKeySecret != ""
}

// resolveCredentials validates the raw credential inputs and resolves
// exactly one of PAT or service-account auth. It rejects both or neither
// credential type being provided, and a service account key pair that is
// only half-provided. Pure function, no I/O — see getCredentials for the
// CLI-facing wrapper that prints and exits on error.
func resolveCredentials(accessToken, accessKeyID, accessKeySecret string) (credentials, error) {
	hasPAT := accessToken != ""
	hasServiceAccount := accessKeyID != "" && accessKeySecret != ""
	hasPartialServiceAccount := (accessKeyID != "") != (accessKeySecret != "")

	switch {
	case hasPartialServiceAccount:
		return credentials{}, fmt.Errorf(
			"both --access-key-id and --access-key-secret " +
				"(or APPKNOX_ACCESS_KEY_ID and APPKNOX_ACCESS_KEY_SECRET) must be provided together")
	case hasPAT && hasServiceAccount:
		return credentials{}, fmt.Errorf(
			"provide either an access token or a service account access key/secret, not both")
	case !hasPAT && !hasServiceAccount:
		return credentials{}, fmt.Errorf(
			"Appknox credentials missing!\n" +
				"Please run 'appknox init' to set an access token,\n" +
				"or set APPKNOX_ACCESS_TOKEN as env for a Personal Access Token,\n" +
				"or set APPKNOX_ACCESS_KEY_ID and APPKNOX_ACCESS_KEY_SECRET as env for a Service Account.")
	}

	return credentials{
		accessToken:     accessToken,
		accessKeyID:     accessKeyID,
		accessKeySecret: accessKeySecret,
	}, nil
}

// getCredentials reads all supported credential flags/env vars and resolves
// them via resolveCredentials, exiting with a clear message on error.
func getCredentials() credentials {
	creds, err := resolveCredentials(
		viper.GetString("access-token"),
		viper.GetString("access-key-id"),
		viper.GetString("access-key-secret"),
	)
	if err != nil {
		fmt.Println(err)
		os.Exit(1)
	}
	return creds
}

// GetHostMappings returns a map of host names to URLs.
func GetHostMappings() map[string]string {
	return map[string]string{
		"global": "https://api.appknox.com/",
		"saudi":  "https://sa.secure.appknox.com/",
		"uae":    "https://secure.uae.appknox.com/",
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
		sort.Strings(availableRegions)
		return "", fmt.Errorf("Invalid region name: %s. Available regions: %s", region, strings.Join(availableRegions, ", "))
	}

	// If neither host nor region are provided, default to the global host
	return hostMappings["global"], nil
}

func getClient() *appknox.Client {
	creds := getCredentials()

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

	var client *appknox.Client
	if creds.isServiceAccount() {
		client, err = appknox.NewClientWithServiceAccount(creds.accessKeyID, creds.accessKeySecret)
	} else {
		client, err = appknox.NewClient(creds.accessToken)
	}
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
