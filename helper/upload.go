package helper

import (
	"context"
	"fmt"
	"os"

	"github.com/cheynewallace/tabby"
)

// ProcessUpload takes the filePath and upload it to the appknox dashboard.
func ProcessUpload(file *os.File) {
	ctx := context.Background()
	client := getClient()
	fileID, err := client.Upload.UploadFile(ctx, file)
	if err != nil {
		fmt.Println(err)
		os.Exit(1)
	}
	t := tabby.New()
	t.AddLine("FileID: ", *fileID)
	t.Print()
}
