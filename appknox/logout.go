package appknox

import (
	"bytes"
	"encoding/json"
	"fmt"
	"io/ioutil"
	"log"
	"net/http"
	"os"

	"github.com/spf13/viper"
)

func Logout() {
	filepath := viper.ConfigFileUsed()
	revokeAccessToken()
	os.Remove(filepath)
}

func revokeAccessToken() {
	var buf bytes.Buffer
	apiBase := viper.GetString("api_base")
	apiHost := viper.GetString("host")
	buf.WriteString(apiHost)
	buf.WriteString(apiBase)
	buf.WriteString("personaltokens")
	url := buf.String()

	client := &http.Client{}
	req, err := http.NewRequest("GET", url, nil)
	if err != nil {
		log.Print(err)
		os.Exit(1)
	}
	req.Header.Set("Content-Type", "application/json")
	req.SetBasicAuth(viper.GetString("user_id"), viper.GetString("token"))

	q := req.URL.Query()
	q.Add("key", viper.GetString("access_token"))
	req.URL.RawQuery = q.Encode()

	resp, err := client.Do(req)
	if err != nil {
		log.Print(err)
		os.Exit(1)
	}
	responseData, err := ioutil.ReadAll(resp.Body)

	type PersonalToken struct {
		Data []struct {
			ID string `json:"id"`
		} `json:"data"`
	}

	var responseObject PersonalToken
	json.Unmarshal(responseData, &responseObject)
	ID := responseObject.Data[0].ID
	buf.WriteString("/")
	buf.WriteString(ID)
	url2 := buf.String()

	reqeust, err := http.NewRequest("DELETE", url2, nil)
	if err != nil {
		log.Print(err)
		os.Exit(1)
	}
	reqeust.Header.Set("Content-Type", "application/json")
	reqeust.SetBasicAuth(viper.GetString("user_id"), viper.GetString("token"))

	response, err := client.Do(reqeust)
	if err != nil {
		log.Print(err)
		os.Exit(1)
	}
	responseData1, err := ioutil.ReadAll(response.Body)
	fmt.Println(string(responseData1))
}
