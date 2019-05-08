package appknox

import (
	"bytes"
	"encoding/json"
	"fmt"
	"io/ioutil"
	"log"
	"net/http"
	"time"

	"github.com/manifoldco/promptui"
	"github.com/spf13/viper"
)

type LoginResponse struct {
	Token  string `json:"token"`
	UserID int    `json:"user_id"`
}

func Login() (*LoginResponse, error) {
	promptHost := promptui.Prompt{
		Label: "Host",
	}

	host, err := promptHost.Run()
	if err != nil {
		fmt.Printf("Prompt failed %v\n", err)
		return nil, err
	}

	promptUsername := promptui.Prompt{
		Label: "Username",
	}

	username, err := promptUsername.Run()
	if err != nil {
		fmt.Printf("Prompt failed %v\n", err)
		return nil, err
	}

	promptPassword := promptui.Prompt{
		Label: "Password",
		Mask:  '*',
	}

	password, err := promptPassword.Run()
	if err != nil {
		fmt.Printf("Prompt failed %v\n", err)
		return nil, err
	}

	var buf1 bytes.Buffer
	apiBase := viper.GetString("api_base")
	viper.Set("host", host)
	viper.WriteConfig()
	apiHost := viper.GetString("host")
	buf1.WriteString(apiHost)
	buf1.WriteString(apiBase)
	buf1.WriteString("login")
	url := buf1.String()
	data := map[string]string{"username": username, "password": password}
	jsonValue, _ := json.Marshal(data)
	resp, err := http.Post(url, "application/json", bytes.NewBuffer(jsonValue))
	if err != nil {
		return nil, err
	}
	responseData, err := ioutil.ReadAll(resp.Body)
	if err != nil {
		return nil, err
	}
	var responseObject LoginResponse
	json.Unmarshal(responseData, &responseObject)
	viper.Set("token", responseObject.Token)
	viper.Set("user_id", responseObject.UserID)
	accessToken := generateAccessToken(username)
	viper.Set("access_token", accessToken)
	viper.WriteConfig()
	return &responseObject, nil
}

func generateAccessToken(username string) string {
	var buf1 bytes.Buffer
	apiBase := viper.GetString("api_base")
	apiHost := viper.GetString("host")
	buf1.WriteString(apiHost)
	buf1.WriteString(apiBase)
	buf1.WriteString("personaltokens")
	url := buf1.String()
	t := time.Now()
	dataString := fmt.Sprintf("appknox-go for %s @%s", username, t.Format("20060102150405"))
	data := map[string]string{"name": dataString}
	jsonValue, _ := json.Marshal(data)
	client := &http.Client{}
	req, err := http.NewRequest("POST", url, bytes.NewBuffer(jsonValue))
	req.Header.Set("Content-Type", "application/json")
	req.SetBasicAuth(viper.GetString("user_id"), viper.GetString("token"))
	resp, err := client.Do(req)
	if err != nil {
		log.Fatal(err)
	}
	responseData, err := ioutil.ReadAll(resp.Body)
	type Responsee struct {
		Data struct {
			Attributes struct {
				Key string `json:"key"`
			} `json:"attributes"`
		} `json:"data"`
	}

	var responseObject Responsee
	json.Unmarshal(responseData, &responseObject)
	accessToken := responseObject.Data.Attributes.Key
	return accessToken
}
