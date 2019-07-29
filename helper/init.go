package helper

import (
	"fmt"
	"os"
	"os/exec"
	"runtime"
	"strings"

	"github.com/spf13/viper"

	"github.com/manifoldco/promptui"
)

//ProcessInit initializes Appknox CLI.
func ProcessInit() {
	host := viper.GetString("host")
	if strings.Contains(host, "https://api.appknox.com") {
		url := "https://secure.appknox.com/settings/developersettings"
		openbrowser(url)
	}

	fmt.Println("Please put the APPKNOX_ACCESS_TOKEN value below.")
	promptAppknoxAccessToken := promptui.Prompt{
		Label: "Access Token",
	}

	appknoxAccessToken, err := promptAppknoxAccessToken.Run()
	if err != nil {
		fmt.Printf("Prompt failed %v\n", err)
		os.Exit(1)
	}
	if appknoxAccessToken == "" {
		fmt.Println("Please enter a valid access token")
		os.Exit(1)
	}
	viper.Set("access-token", appknoxAccessToken)
	_, err = CheckToken()
	if err != nil {
		fmt.Println("Please enter a valid access token")
		os.Exit(1)
	}
	viper.WriteConfig()
	fmt.Println("Appknox CLI has been initialized.")
}

func openbrowser(url string) {
	var err error

	switch runtime.GOOS {
	case "linux":
		err = exec.Command("xdg-open", url).Start()
	case "windows":
		err = exec.Command("rundll32", "url.dll,FileProtocolHandler", url).Start()
	case "darwin":
		err = exec.Command("open", url).Start()
	default:
		fmt.Println("Please go to " + url + " generate Appknox access token")
	}
	if err != nil {
		fmt.Println("Please go to " + url + " generate Appknox access token")
	}
}
