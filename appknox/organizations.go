package appknox

import (
	"bytes"
	"encoding/json"
	"io/ioutil"
	"net/http"

	"github.com/spf13/viper"
)

type OrgResponse struct {
	Results []struct {
		ID   int    `json:"id"`
		Name string `json:"name"`
	} `json:"results"`
}

func Organizations() (*OrgResponse, error) {
	token := viper.GetString("token")
	userID := viper.GetString("user_id")
	var buf1 bytes.Buffer
	apiBase := viper.GetString("api_base")
	apiHost := viper.GetString("host")
	buf1.WriteString(apiHost)
	buf1.WriteString(apiBase)
	buf1.WriteString("organizations")
	url := buf1.String()
	req, err := http.NewRequest("GET", url, nil)
	if err != nil {
		return nil, err
	}
	q := req.URL.Query()
	q.Add("token", token)
	q.Add("user", userID)
	req.URL.RawQuery = q.Encode()

	resp, err := http.Get(req.URL.String())

	if err != nil {
		return nil, err
	}
	responseData, err := ioutil.ReadAll(resp.Body)

	if err != nil {
		return nil, err
	}

	var responseObject OrgResponse
	json.Unmarshal(responseData, &responseObject)
	return &responseObject, nil
}
