package gitrepo

import (
	"context"
	"go/ast"
	"go/parser"
	"go/token"
	"io/ioutil"
	"os"
	"strconv"
	"strings"

	"github.com/google/go-github/v53/github" // with go modules enabled (GO111MODULE=on or outside GOPATH)
	log "github.com/yomaytk/go_ltrace/log"
	uutil "github.com/yomaytk/go_ltrace/util"
	"golang.org/x/oauth2"
	"golang.org/x/xerrors"
)

var CACHE_FILE = "./cache"

type LangDiffOperation interface{}

type FuncSignature struct {
	Name string `json:"name"`
	Args []string
}

type FuncLocation struct {
	FuncName  string `json:"name"`
	StartLine int    `json:"start_line"`
	EndLine   int    `json:"end_line"`
}

type GithubOperation struct {
	TokenSource oauth2.TokenSource
}

func NewGithubOperation() *GithubOperation {
	ts := oauth2.StaticTokenSource(
		&oauth2.Token{AccessToken: os.Getenv("GITHUB_ACCESS_TOKEN")},
	)
	return &GithubOperation{TokenSource: ts}
}

func (ghop GithubOperation) NewGithubClient() (context.Context, *github.Client) {
	ctx := context.Background()
	tc := oauth2.NewClient(ctx, ghop.TokenSource)
	client := github.NewClient(tc)
	return ctx, client
}

func (ghop GithubOperation) GetFixedFilesFromCommit(git_url string) (map[string]bool, error) {
	tokens := strings.Split(git_url, "/")
	if strings.Compare(tokens[len(tokens)-2], "commit") == 0 {

		fixed_files := map[string]bool{}
		// initialize authorization info
		ctx, client := ghop.NewGithubClient()

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

		fixed_files := map[string]bool{}
		// initialize authorization info
		ctx, client := ghop.NewGithubClient()

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

		func_signatures := []FuncSignature{}
		// initialize authorization info
		ctx, client := ghop.NewGithubClient()

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

func (ghop GithubOperation) GetPreCommitFuncLocation(git_url string, file_path string) ([]FuncLocation, error) {

	func_locations := []FuncLocation{}
	tokens := strings.Split(git_url, "\n")

	// initialize authorization info
	ctx, client := ghop.NewGithubClient()

	// get the commit info
	owner := tokens[len(tokens)-4]
	repo := tokens[len(tokens)-3]
	commit_sha := tokens[len(tokens)-1]

	// get the target commit
	repo_commit, _, err := client.Repositories.GetCommit(ctx, owner, repo, commit_sha, nil)
	uutil.ErrFatal(err)
	if len(repo_commit.Parents) > 1 {
		log.Logger.Infoln("WARNING: target commit has multiple parents.\n")
	} else if len(repo_commit.Parents) == 0 {
		return []FuncLocation{}, xerrors.Errorf("Bug: commit don't has the parents commit at GerPreCommitFuncLocation.\n")
	}

	// get the file content before target commit (use the parent of target commit)
	ctx2, client2 := ghop.NewGithubClient()
	pre_commit_sha := repo_commit.Parents[0].GetSHA()
	file_content, _, _, err := client2.Repositories.GetContents(ctx2, owner, repo, file_path, &github.RepositoryContentGetOptions{Ref: pre_commit_sha})
	uutil.ErrFatal(err)
	content, err := file_content.GetContent()
	uutil.ErrFatal(err)

	// parse the file content and get function location
	fset := token.NewFileSet()
	f, err := parser.ParseFile(fset, "", content, 0)
	uutil.ErrFatal(err)

	for _, decl := range f.Decls {
		if fn, ok := decl.(*ast.FuncDecl); ok {
			func_name := fn.Name.Name
			start_line := fset.Position(fn.Pos()).Line - 1
			end_line := fset.Position(fn.End()).Line - 1
			func_location := FuncLocation{FuncName: func_name, StartLine: start_line, EndLine: end_line}
			func_locations = append(func_locations, func_location)
		}
	}

	return func_locations, nil
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
