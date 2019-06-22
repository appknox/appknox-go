package appknox

import (
	"bytes"
	"encoding/json"
	"fmt"
	"io/ioutil"
	"net/http"
	"os"
	"strconv"
)

type UploadResponse struct {
	URL           string `json:"url"`
	FileKey       string `json:"file_key"`
	FileKeySigned string `json:"file_key_signed"`
}

type MeResponse struct {
	DefaultOrganization int `json:"default_organization"`
}

type DetailErrorResponse struct {
	Detail string `json:"detail"`
}

func Upload(args []string) {
	filePath := args[0]
	var buf1 bytes.Buffer
	var buf2 bytes.Buffer
	apiBase := "api/"
	apiHost := "https://api.appknox.com/"
	accessToken := os.Getenv("APPKNOX_TOKEN")
	if accessToken == "" {
		fmt.Println("APPKNOX_TOKEN is no set in env")
		os.Exit(1)
	}
	buf1.WriteString(apiHost)
	buf1.WriteString(apiBase)
	buf2.WriteString("Token ")
	buf2.WriteString(accessToken)
	meURL := "https://api.appknox.com/api/me"
	client1 := &http.Client{}
	req1, err := http.NewRequest("GET", meURL, nil)
	if err != nil {
		fmt.Println(err)
		os.Exit(1)
	}
	req1.Header.Set("Content-Type", "application/json")
	req1.Header.Set("Authorization", buf2.String())
	meResponse, err := client1.Do(req1)
	if err != nil {
		fmt.Println(err)
		os.Exit(1)
	}
	meResponseData, err := ioutil.ReadAll(meResponse.Body)
	if meResponse.StatusCode != 200 {
		var errorResp DetailErrorResponse
		json.Unmarshal(meResponseData, &errorResp)
		fmt.Println(errorResp.Detail)
		os.Exit(1)
	}
	var responseObject MeResponse
	json.Unmarshal(meResponseData, &responseObject)
	organizationID := responseObject.DefaultOrganization
	strOrgID := strconv.Itoa(organizationID)
	orgURL := fmt.Sprintf("organizations/%s/upload_app", strOrgID)
	buf1.WriteString(orgURL)
	url2 := buf1.String()
	client2 := &http.Client{}
	req2, err := http.NewRequest("GET", url2, nil)
	if err != nil {
		fmt.Println(err)
		os.Exit(1)
	}
	req2.Header.Set("Content-Type", "application/json")
	req2.Header.Set("Authorization", buf2.String())

	response, err := client2.Do(req2)
	if err != nil {
		fmt.Println(err)
		os.Exit(1)
	}
	responseData, err := ioutil.ReadAll(response.Body)

	var orgResponseObject UploadResponse
	json.Unmarshal(responseData, &orgResponseObject)
	fileReader, err := os.Open(filePath)
	// If any error fail quickly here.
	if err != nil {
		fmt.Println(err)
		os.Exit(1)
	}
	defer fileReader.Close()

	// Save the file stat.
	fileStat, err := fileReader.Stat()
	if err != nil {
		fmt.Println(err)
		os.Exit(1)
	}

	// Save the file size.
	fileSize := fileStat.Size()
	if err != nil {
		fmt.Println(err)
		os.Exit(1)
	}

	client3 := &http.Client{}
	URL := orgResponseObject.URL
	req3, err := http.NewRequest("PUT", URL, fileReader)
	if err != nil {
		fmt.Println(err)
		os.Exit(1)
	}
	req3.Header.Set("Content-Type", "application/octet-stream")
	req3.ContentLength = fileSize
	client3.Do(req3)

	data1 := map[string]string{"url": orgResponseObject.URL,
		"file_key":        orgResponseObject.FileKey,
		"file_key_signed": orgResponseObject.FileKeySigned}

	jsonValue1, _ := json.Marshal(data1)
	client4 := &http.Client{}
	req4, err := http.NewRequest("POST", url2, bytes.NewBuffer(jsonValue1))
	if err != nil {
		fmt.Println(err)
		os.Exit(1)
	}
	req4.Header.Set("Content-Type", "application/json")
	req4.Header.Set("Authorization", buf2.String())
	_, err1 := client4.Do(req4)
	if err1 != nil {
		fmt.Println(err1)
		os.Exit(1)
	}
	fmt.Println("File Uploaded Successfully.")
}
