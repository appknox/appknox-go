package helper

import (
	"context"
	"os"
	"strings"
	"time"

	"github.com/appknox/appknox-go/appknox"
	"github.com/cheynewallace/tabby"
	"github.com/vbauerster/mpb/v4"
	"github.com/vbauerster/mpb/v4/decor"
)

// UploadOptions is what an upload records besides the binary.
// An empty GitBranch or GitRepo is filled from CI (GITHUB_BASE_REF / GITHUB_REF,
// GITHUB_REPOSITORY) so a later autofix run can find this file by branch.
type UploadOptions struct {
	KnoxIQ    bool
	GitBranch string
	GitRepo   string
}

// ProcessUpload takes the filePath and uploads it to the appknox dashboard.
// KnoxIQ requests KnoxIQ triage for this build once SAST completes.
func ProcessUpload(file *os.File, opt UploadOptions) {
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
	opt = fillUploadFromCI(opt)
	submissionID, err := client.Upload.UploadFileUsingReader(ctx, filewithbar, fileSize, appknox.UploadOptions{
		KnoxIQ:    opt.KnoxIQ,
		GitBranch: opt.GitBranch,
		GitRepo:   opt.GitRepo,
	})
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

// fillUploadFromCI stamps the checkout the same way autofix resolves its base
// branch, so `appknox upload` followed by `appknox autofix` agree on the file.
func fillUploadFromCI(opt UploadOptions) UploadOptions {
	ci := applyCIDefaults(AutofixOptions{})
	if strings.TrimSpace(opt.GitRepo) == "" {
		opt.GitRepo = ci.Repo
	}
	if strings.TrimSpace(opt.GitBranch) == "" {
		opt.GitBranch = ci.Ref
	}
	return opt
}
