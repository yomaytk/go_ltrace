package gitrepo

import (
	"fmt"
	"reflect"
	"strings"
	"testing"

	log "github.com/yomaytk/go_ltrace/log"
	uutil "github.com/yomaytk/go_ltrace/util"
	gity "github.com/yomaytk/go_ltrace/vulndb/gitrepo/types"
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

	ans_file_func_locations := map[string][]gity.FuncLocation{
		"configuration/configuration.go": {gity.NewFuncLocation("UnmarshalYAML", "*Version", []string{"func(interface{}) error"}, []string{"error"}, 372, 390), gity.NewFuncLocation("UnmarshalYAML", "*Loglevel", []string{"func(interface{}) error"}, []string{"error"}, 402, 418), gity.NewFuncLocation("Type", "Storage", []string{}, []string{"string"}, 427, 452), gity.NewFuncLocation("Parameters", "Storage", []string{}, []string{"Parameters"}, 455, 457), gity.NewFuncLocation("setParameter", "Storage", []string{"string", "interface{}"}, []string{}, 460, 462), gity.NewFuncLocation("UnmarshalYAML", "*Storage", []string{"func(interface{}) error"}, []string{"error"}, 466, 503), gity.NewFuncLocation("MarshalYAML", "Storage", []string{}, []string{"interface{}", "error"}, 506, 511), gity.NewFuncLocation("Type", "Auth", []string{}, []string{"string"}, 517, 523), gity.NewFuncLocation("Parameters", "Auth", []string{}, []string{"Parameters"}, 526, 528), gity.NewFuncLocation("setParameter", "Auth", []string{"string", "interface{}"}, []string{}, 531, 533), gity.NewFuncLocation("UnmarshalYAML", "*Auth", []string{"func(interface{}) error"}, []string{"error"}, 537, 564), gity.NewFuncLocation("MarshalYAML", "Auth", []string{}, []string{"interface{}", "error"}, 567, 572), gity.NewFuncLocation("Parse", "", []string{"io.Reader"}, []string{"*Configuratin", "error"}, 667, 706)},
	}

	file_func_locations, err := ghop.GetPreCommitFuncLocation(SampleCommitURL, file_diffs)
	uutil.ErrFatal(err)

	t.Run("FileFuncLocation Size Test", func(t *testing.T) {
		if len(file_func_locations) != len(ans_file_func_locations) {
			t.Fatalf("Test Error: Content: %v, Answer: %v\n", len(file_func_locations), len(ans_file_func_locations))
		}
	})

	t.Run("FileFuncLocation Equal Test", func(t *testing.T) {
		for path, ans_func_locations := range ans_file_func_locations {
			if !reflect.DeepEqual(file_func_locations[path], ans_func_locations) {
				t.Fatalf("Test Error: Content: %+v, Answer: %+v\n", file_func_locations[path], ans_file_func_locations[path])
			}
		}
	})

	fmt.Println(file_func_locations)

}
