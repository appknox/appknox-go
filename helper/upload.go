package helper

import (
	"context"
	"os"
	"time"

	"github.com/cheynewallace/tabby"
	"github.com/vbauerster/mpb/v4"
	"github.com/vbauerster/mpb/v4/decor"
)

// ProcessUpload takes the filePath and upload it to the appknox dashboard.
func ProcessUpload(file *os.File) {
	ctx := context.Background()
	client := getClient()
	stat, _ := file.Stat()
	fileSize := stat.Size()
	p := mpb.New(
		mpb.WithWidth(60),
		mpb.WithRefreshRate(180*time.Millisecond),
		mpb.WithOutput(os.Stderr),
	)
	bar := p.AddBar(fileSize, mpb.BarStyle("[=>-|"),
		mpb.PrependDecorators(
			decor.CountersKibiByte("% 6.1f / % 6.1f"),
		),
		mpb.AppendDecorators(
			decor.EwmaETA(decor.ET_STYLE_MMSS, float64(fileSize)/2048),
			decor.Name(" ] "),
			decor.AverageSpeed(decor.UnitKiB, "% .2f"),
		),
	)
	filewithbar := bar.ProxyReader(file)
	submissionID, err := client.Upload.UploadFileUsingReader(ctx, filewithbar, fileSize)
	if err != nil {
		PrintError(err)
		os.Exit(1)
	}
	akFile, _, err := client.Upload.CheckSubmission(ctx, *submissionID)
	if err != nil {
		PrintError(err)
		os.Exit(1)
	}
	t := tabby.New()
	t.AddLine(akFile.ID)
	t.Print()
}
