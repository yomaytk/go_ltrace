package gitrepo

import (
	"context"
	"io/ioutil"
	"os"
	"strconv"
	"strings"

	"github.com/google/go-github/v53/github" // with go modules enabled (GO111MODULE=on or outside GOPATH)
	uutil "github.com/yomaytk/go_ltrace/util"
	"golang.org/x/oauth2"
	"golang.org/x/xerrors"
)

var CACHE_FILE = "./cache"

type GithubOperation struct {
	TokenSource oauth2.TokenSource
}

type FuncSignature struct {
	Name string `json:"name"`
	Args []string
}

func NewGithubOperation() *GithubOperation {
	ts := oauth2.StaticTokenSource(
		&oauth2.Token{AccessToken: os.Getenv("GITHUB_ACCESS_TOKEN")},
	)
	return &GithubOperation{TokenSource: ts}
}

func (ghop GithubOperation) GetFixedFilesFromCommit(git_url string) (map[string]bool, error) {
	tokens := strings.Split(git_url, "/")
	if strings.Compare(tokens[len(tokens)-2], "commit") == 0 {

		// initialize authorization info
		fixed_files := map[string]bool{}
		ctx := context.Background()
		tc := oauth2.NewClient(ctx, ghop.TokenSource)
		client := github.NewClient(tc)

		owner := tokens[len(tokens)-4]
		repo := tokens[len(tokens)-3]
		commit_sha := tokens[len(tokens)-1]

		repo_commit, _, err := client.Repositories.GetCommit(ctx, owner, repo, commit_sha, nil)
		uutil.ErrFatal(err)

		for _, fixed_file := range repo_commit.Files {
			fixed_files[*fixed_file.Filename] = true
		}

		return fixed_files, nil
	} else {
		return map[string]bool{}, xerrors.Errorf("Bug: Strange github url at GetFixedFilesFromCommit. '%v'\n", git_url)
	}
}

func (ghop GithubOperation) GetFixedFilesFromPullRequest(git_url string) (map[string]bool, error) {

	if strings.Contains(git_url, "/commits/") {
		git_url = strings.Split(git_url, "/commits/")[0]
	}

	tokens := strings.Split(git_url, "/")
	if strings.Compare(tokens[len(tokens)-2], "pull") == 0 {

		// initialize authorization info
		fixed_files := map[string]bool{}
		ctx := context.Background()
		tc := oauth2.NewClient(ctx, ghop.TokenSource)
		client := github.NewClient(tc)

		owner := tokens[len(tokens)-4]
		repo := tokens[len(tokens)-3]
		pull_num, err := strconv.Atoi(tokens[len(tokens)-1])
		uutil.ErrFatal(err)

		files, _, err := client.PullRequests.ListFiles(ctx, owner, repo, pull_num, nil)
		uutil.ErrFatal(err)

		for _, file := range files {
			fixed_files[*file.Filename] = true
		}

		return fixed_files, nil
	} else {
		return map[string]bool{}, xerrors.Errorf("Bug: Strange github url at GetFixedFilesFromPullRequest. '%v'\n", git_url)
	}
}

func (ghop GithubOperation) GetDiffFromCommit(git_url string) ([]FuncSignature, error) {
	tokens := strings.Split(git_url, "/")
	if strings.Compare(tokens[len(tokens)-2], "commit") == 0 {

		// initialize authorization info
		func_signatures := []FuncSignature{}
		ctx := context.Background()
		tc := oauth2.NewClient(ctx, ghop.TokenSource)
		client := github.NewClient(tc)

		owner := tokens[len(tokens)-4]
		repo := tokens[len(tokens)-3]
		commit_sha := tokens[len(tokens)-1]

		repo_commit, _, err := client.Repositories.GetCommit(ctx, owner, repo, commit_sha, nil)
		uutil.ErrFatal(err)

		var diff_content string
		for _, file := range repo_commit.Files {
			file_name := *file.Filename
			diff_content = diff_content + "\n\n" + file_name + "\n\n" + file.GetPatch()
		}
		err = ioutil.WriteFile(CACHE_FILE, []byte(diff_content), 0644)
		uutil.ErrFatal(err)

		return func_signatures, nil
	} else {
		return []FuncSignature{}, xerrors.Errorf("Bug: Strange github url at GetDiffFromCommit. '%v'\n", git_url)
	}
}

func (ghop GithubOperation) GetFixedFiles(git_url string) (map[string]bool, error) {

	if strings.Contains(git_url, "/commit/") {
		fixed_files, err := ghop.GetFixedFilesFromCommit(git_url)
		uutil.ErrFatal(err)
		return fixed_files, nil
	} else if strings.Contains(git_url, "/pull/") {
		fixed_files, err := ghop.GetFixedFilesFromPullRequest(git_url)
		uutil.ErrFatal(err)
		return fixed_files, nil
	} else {
		return map[string]bool{}, xerrors.Errorf("strange github url: %v\n", git_url)
	}

}
