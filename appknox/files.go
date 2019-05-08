package appknox

import (
	"bytes"
	"encoding/json"
	"io/ioutil"
	"log"
	"net/http"
	"os"
	"time"

	"github.com/spf13/viper"
)

type FileResponse struct {
	Results []struct {
		ID                 int       `json:"id"`
		Name               string    `json:"name"`
		Version            string    `json:"version"`
		VersionCode        string    `json:"version_code"`
		DynamicStatus      int       `json:"dynamic_status"`
		APIScanProgress    int       `json:"api_scan_progress"`
		IsStaticDone       bool      `json:"is_static_done"`
		IsDynamicDone      bool      `json:"is_dynamic_done"`
		StaticScanProgress int       `json:"static_scan_progress"`
		APIScanStatus      int       `json:"api_scan_status"`
		Rating             string    `json:"rating"`
		IsManualDone       bool      `json:"is_manual_done"`
		IsAPIDone          bool      `json:"is_api_done"`
		CreatedOn          time.Time `json:"created_on"`
	} `json:"results"`
}

func Files(args []string) *FileResponse {
	var buf1 bytes.Buffer
	var buf2 bytes.Buffer
	apiBase := viper.GetString("api_base")
	apiHost := viper.GetString("host")
	buf1.WriteString(apiHost)
	buf1.WriteString(apiBase)
	buf1.WriteString("projects/")
	buf1.WriteString(args[0])
	buf1.WriteString("/files")
	url := buf1.String()

	client := &http.Client{}
	req, err := http.NewRequest("GET", url, nil)
	if err != nil {
		log.Print(err)
		os.Exit(1)
	}
	req.Header.Set("Content-Type", "application/json")

	buf2.WriteString("Token ")
	buf2.WriteString(viper.GetString("access_token"))
	req.Header.Set("Authorization", buf2.String())

	resp, err := client.Do(req)
	if err != nil {
		log.Print(err)
		os.Exit(1)
	}

	responseData, err := ioutil.ReadAll(resp.Body)
	var responseObject FileResponse
	json.Unmarshal(responseData, &responseObject)
	return &responseObject
}
