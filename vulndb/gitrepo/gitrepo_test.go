package gitrepo

import (
	"fmt"
	"strings"
	"testing"

	log "github.com/yomaytk/go_ltrace/log"
	uutil "github.com/yomaytk/go_ltrace/util"
)

var (
	SampleCommitURL = "https://github.com/distribution/distribution/commit/f55a6552b006a381d9167e328808565dd2bf77dc"
	SamplePRURL     = "https://github.com/hashicorp/vault/pull/19495/files"
)

func TestCommitDiff(t *testing.T) {

	// initialize logger
	log.InitLogger()
	defer log.Logger.Sync()

	ghop := NewGithubOperation()

	ans_file_diffs := []FileDiff{
		{FilePath: "configuration/configuration.go", Content: ""},
		{FilePath: "configuration/configuration_test.go", Content: ""},
		{FilePath: "registry/api/v2/descriptors.go", Content: ""},
		{FilePath: "registry/api/v2/errors.go", Content: ""},
		{FilePath: "registry/handlers/api_test.go", Content: ""},
		{FilePath: "registry/handlers/catalog.go", Content: ""},
	}

	file_diffs, err := ghop.GetDiffFromCommit(SampleCommitURL)
	uutil.ErrFatal(err)

	for i := 0; i < len(file_diffs); i++ {
		t.Run("FileDiff.FilePath Test", func(t *testing.T) {
			if strings.Compare(ans_file_diffs[i].FilePath, file_diffs[i].FilePath) != 0 {
				t.Fatalf("Test Error: Content: %v, Answer: %v\n", file_diffs[i].FilePath, ans_file_diffs[i].FilePath)
			}
		})
	}

	// ans_file_func_locations := map[string][]FuncLocation{
	// 	"configuration/configuration.go": {{FuncName: "UnmarshalYAML", StartLine: 372, EndLine: 390}, {FuncName: }}
	// }

	file_func_locations, err := ghop.GetPreCommitFuncLocation(SampleCommitURL, file_diffs)
	uutil.ErrFatal(err)

	fmt.Println(file_func_locations)

}
