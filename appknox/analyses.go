package appknox

import (
	"bytes"
	"encoding/json"
	"io/ioutil"
	"net/http"
	"time"

	"github.com/spf13/viper"
)

type AnalysesResponse struct {
	Results []struct {
		ID            int       `json:"id"`
		Risk          int       `json:"risk"`
		Status        int       `json:"status"`
		CvssVector    string    `json:"cvss_vector"`
		CvssBase      float64   `json:"cvss_base"`
		CvssVersion   int       `json:"cvss_version"`
		Owasp         []string  `json:"owasp"`
		UpdatedOn     time.Time `json:"updated_on"`
		Vulnerability struct {
			ID int `json:"id"`
		} `json:"vulnerability"`
	} `json:"results"`
}

func Analyses(args []string) (*AnalysesResponse, error) {
	var buf1 bytes.Buffer
	var buf2 bytes.Buffer
	apiBase := viper.GetString("api_base")
	apiHost := viper.GetString("host")
	buf1.WriteString(apiHost)
	buf1.WriteString(apiBase)
	buf1.WriteString("v2/files/")
	buf1.WriteString(args[0])
	buf1.WriteString("/analyses")

	url := buf1.String()

	client := &http.Client{}
	req, err := http.NewRequest("GET", url, nil)
	if err != nil {
		return nil, err
	}
	req.Header.Set("Content-Type", "application/json")

	buf2.WriteString("Token ")
	buf2.WriteString(viper.GetString("access_token"))
	req.Header.Set("Authorization", buf2.String())

	resp, err := client.Do(req)
	if err != nil {
		return nil, err
	}
	responseData, err := ioutil.ReadAll(resp.Body)

	var responseObject AnalysesResponse
	json.Unmarshal(responseData, &responseObject)
	return &responseObject, nil
}
