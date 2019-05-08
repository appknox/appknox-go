package appknox

import (
	"bytes"
	"encoding/json"
	"fmt"
	"io/ioutil"
	"net/http"
	"time"

	"github.com/spf13/viper"
)

type ProjectResponse struct {
	Results []struct {
		ID          int       `json:"id"`
		CreatedOn   time.Time `json:"created_on"`
		UpdatedOn   time.Time `json:"updated_on"`
		PackageName string    `json:"package_name"`
		Platform    int       `json:"platform"`
		FileCount   int       `json:"file_count"`
	} `json:"results"`
}

func Projects() (*ProjectResponse, error) {
	var buf1 bytes.Buffer
	var buf2 bytes.Buffer
	apiBase := viper.GetString("api_base")
	apiHost := viper.GetString("host")
	buf1.WriteString(apiHost)
	buf1.WriteString(apiBase)
	organizationID := viper.GetString("organization_id")
	slagURL := fmt.Sprintf("organizations/%s/projects", organizationID)
	buf1.WriteString(slagURL)
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

	q := req.URL.Query()
	q.Add("package_name", "")
	q.Add("search", "")
	req.URL.RawQuery = q.Encode()

	resp, err := client.Do(req)
	if err != nil {
		return nil, err
	}
	responseData1, err := ioutil.ReadAll(resp.Body)

	var responseObject ProjectResponse
	json.Unmarshal(responseData1, &responseObject)
	return &responseObject, nil
}
