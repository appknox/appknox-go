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

func Rescan(args []string) {
	var buf1 bytes.Buffer
	var buf2 bytes.Buffer
	apiBase := viper.GetString("api_base")
	apiHost := viper.GetString("host")
	buf1.WriteString(apiHost)
	buf1.WriteString(apiBase)
	buf1.WriteString("rescan")
	url := buf1.String()
	fileID := args[0]
	fmt.Println(fileID)
	data := map[string]string{"file_id": fileID}
	fmt.Println(data)
	jsonValue, _ := json.Marshal(data)
	client := &http.Client{}
	req, err := http.NewRequest("POST", url, bytes.NewBuffer(jsonValue))
	if err != nil {
		log.Print(err)
		os.Exit(1)
	}
	req.Header.Set("Content-Type", "application/json")

	buf2.WriteString("Token ")
	buf2.WriteString(viper.GetString("access_token"))
	req.Header.Set("Authorization", buf2.String())

	fmt.Println(req.Body)
	resp, err := client.Do(req)
	if err != nil {
		log.Print(err)
		os.Exit(1)
	}
	fmt.Println(resp.StatusCode)
	responseData, err := ioutil.ReadAll(resp.Body)
	fmt.Println(string(responseData))
}
