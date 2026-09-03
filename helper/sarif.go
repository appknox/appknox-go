package helper

import (
	"fmt"
	"os"
	"time"

	"github.com/appknox/appknox-go/appknox"
)

func ConvertToSARIFReport(fileID int, riskThreshold int, filePath string, staticScanTimeout time.Duration) error {
	client := getClient()
	sarif, err := appknox.GenerateSARIFGivenFileID(client, fileID, riskThreshold, staticScanTimeout)
	if err != nil {
		return err
	}
	sarifContent, err := appknox.GenerateSARIFFileContent(sarif)
	if err != nil {
		return err
	}
	file, err := os.Create(filePath)
	if err != nil {
		return err
	}
	defer file.Close()

	_, err = file.Write([]byte(sarifContent))
	if err != nil {
		return err
	}
	fmt.Println("SARIF report created successfully at:", filePath)
	return nil
}
