package gitrepo

import (
	"context"
	"fmt"
	"go/ast"
	"go/parser"
	"go/token"
	"os"
	"strconv"
	"strings"

	"github.com/google/go-github/v53/github" // with go modules enabled (GO111MODULE=on or outside GOPATH)
	"github.com/yomaytk/go_ltrace/pkg/language/goscan"
	uutil "github.com/yomaytk/go_ltrace/util"
	gity "github.com/yomaytk/go_ltrace/vulndb/gitrepo/types"
	"golang.org/x/oauth2"
	"golang.org/x/xerrors"
)

var CACHE_FILE = "./cache"

type LangDiffOperation interface{}

type FileDiff struct {
	FilePath string
	Content  string
}

type DiffType uint8

const (
	Addition DiffType = iota
	Deletion
)

type DiffLines struct {
	Type   DiffType
	Start  int
	Length int
}

type GithubOperation struct {
	TokenSource oauth2.TokenSource
}

func NewGithubOperation() *GithubOperation {
	ts := oauth2.StaticTokenSource(
		&oauth2.Token{AccessToken: os.Getenv("GITHUB_ACCESS_TOKEN")},
	)
	return &GithubOperation{ts}
}

func (ghop GithubOperation) NewGithubClient() (context.Context, *github.Client) {
	ctx := context.Background()
	tc := oauth2.NewClient(ctx, ghop.TokenSource)
	client := github.NewClient(tc)
	return ctx, client
}

func (ghop GithubOperation) getFixedLocation(file_diff *FileDiff) ([]DiffLines, error) {
	diff_liness := []DiffLines{}
	lines := strings.Split(file_diff.Content, "\n")
	id := 0
	if strings.HasPrefix(lines[id], "@@") {
		// get hunk header info
		tokens := strings.Fields(lines[id])
		before_header := strings.Split(tokens[1], ",")
		after_header := strings.Split(tokens[2], ",")

		if !strings.HasPrefix(before_header[0], "-") {
			return diff_liness, xerrors.Errorf("Bug: Strange git huk deletion header at getFixedLocation.\n")
		}

		before_start_l, err := strconv.Atoi(before_header[0])
		before_start_l *= -1
		uutil.ErrFatal(err)
		_, err = strconv.Atoi(before_header[1])
		uutil.ErrFatal(err)

		after_start_l, err := strconv.Atoi(after_header[0])
		uutil.ErrFatal(err)
		_, err = strconv.Atoi(before_header[1])
		uutil.ErrFatal(err)

		// start reading of deletion and addition
		id++

		deletion_start_l := -1
		addition_start_l := -1
		before_l := before_start_l - 1
		after_l := after_start_l - 1

		for id < len(lines) {
			if strings.HasPrefix(lines[id], "-") {
				// get deletions
				if deletion_start_l != -1 {
					return diff_liness, xerrors.Errorf("Bug: get deletions error at getFixedLocation.\n")
				}
				before_l++
				deletion_start_l = before_l
				id++
				for ; ; id++ {
					if strings.HasPrefix(lines[id], "-") {
						before_l++
					} else {
						break
					}
				}
				diff_liness = append(diff_liness, DiffLines{Type: Deletion, Start: deletion_start_l, Length: before_l - deletion_start_l + 1})
				deletion_start_l = -1
			} else if strings.HasPrefix(lines[id], "+") {
				// get additions
				if addition_start_l != -1 {
					return diff_liness, xerrors.Errorf("Bug: get additions error at getFixedLocation.\n")
				}
				after_l++
				addition_start_l = after_l
				id++
				for ; ; id++ {
					if strings.HasPrefix(lines[id], "+") {
						after_l++
					} else {
						break
					}
				}
				diff_liness = append(diff_liness, DiffLines{Type: Addition, Start: addition_start_l, Length: after_l - addition_start_l})
				addition_start_l = -1
			} else {
				id++
				before_l++
				after_l++
			}
		}
	} else {
		return diff_liness, xerrors.Errorf("Bug: Strange github hunk header at getFixedLocatin.\n")
	}
	return diff_liness, nil
}

func (ghop GithubOperation) GetDiffFromCommit(git_url string) ([]FileDiff, error) {
	file_diffs := []FileDiff{}

	tokens := strings.Split(git_url, "/")
	if strings.Compare(tokens[len(tokens)-2], "commit") == 0 {

		// initialize authorization info
		ctx, client := ghop.NewGithubClient()

		owner := tokens[len(tokens)-4]
		repo := tokens[len(tokens)-3]
		commit_sha := tokens[len(tokens)-1]

		repo_commit, _, err := client.Repositories.GetCommit(ctx, owner, repo, commit_sha, nil)
		uutil.ErrFatal(err)

		for _, file := range repo_commit.Files {
			file_path := *file.Filename
			file_diffs = append(file_diffs, FileDiff{FilePath: file_path, Content: file.GetPatch()})
		}

		return file_diffs, nil
	} else {
		return file_diffs, xerrors.Errorf("Bug: Strange github url at GetDiffFromCommit. '%v'\n", git_url)
	}
}

func (ghop GithubOperation) GetDiffFromPR(git_url string) ([]FileDiff, error) {
	file_diffs := []FileDiff{}

	if strings.Contains(git_url, "/commits/") {
		git_url = strings.Split(git_url, "/commits/")[0]
	}

	tokens := strings.Split(git_url, "/")
	if strings.Compare(tokens[len(tokens)-2], "pull") == 0 {

		// initialize authorization info
		ctx, client := ghop.NewGithubClient()

		owner := tokens[len(tokens)-4]
		repo := tokens[len(tokens)-3]
		pull_num, err := strconv.Atoi(tokens[len(tokens)-1])
		uutil.ErrFatal(err)

		files, _, err := client.PullRequests.ListFiles(ctx, owner, repo, pull_num, nil)
		uutil.ErrFatal(err)

		for _, file := range files {
			file_path := *file.Filename
			file_diffs = append(file_diffs, FileDiff{FilePath: file_path, Content: file.GetPatch()})
		}

		return file_diffs, nil
	} else {
		return file_diffs, xerrors.Errorf("Bug: Strange github url at GetFixedFilesFromPullRequest. '%v'\n", git_url)
	}
}

func (ghop GithubOperation) GetPrePRFuncLocation(git_url string, file_diffs []FileDiff) (map[string][]gity.FuncLocation, error) {
	file_func_locations := map[string][]gity.FuncLocation{}

	if strings.Contains(git_url, "/commits/") {
		git_url = strings.Split(git_url, "/commits/")[0]
	}

	tokens := strings.Split(git_url, "/")
	if strings.Compare(tokens[len(tokens)-2], "pull") == 0 {

		// initialize authorization info
		ctx, client := ghop.NewGithubClient()

		owner := tokens[len(tokens)-4]
		repo := tokens[len(tokens)-3]
		pull_num, err := strconv.Atoi(tokens[len(tokens)-1])
		uutil.ErrFatal(err)

		commits, _, err := client.PullRequests.ListCommits(ctx, owner, repo, pull_num, nil)
		uutil.ErrFatal(err)

		if commits == nil || len(commits) <= 0 {
			return file_func_locations, xerrors.Errorf("Bug: this PR doesn't have commits at GetPrePRFuncLocation.\n")
		}

		// parents of the first commit of this PR
		pre_commits := commits[0].Parents

		if len(pre_commits) > 1 {
			fmt.Printf("WARNING: target commit has %v parents. \n", len(pre_commits))
			parents := pre_commits
			for i := 0; i < len(pre_commits); i++ {
				fmt.Printf("Parent_%v: %v\n", i, parents[i].GetSHA())
			}
		} else if len(pre_commits) == 0 {
			return map[string][]gity.FuncLocation{}, xerrors.Errorf("Bug: the commit don't has the parents commit at GetPrePRFuncLocation.\n")
		}

		pre_commit_sha := *pre_commits[0].SHA

		for _, file_diff := range file_diffs {
			// get the file content before target commit (use the parent of target commit)
			file_path := file_diff.FilePath
			ctx2, client2 := ghop.NewGithubClient()
			file_content, _, _, err := client2.Repositories.GetContents(ctx2, owner, repo, file_path, &github.RepositoryContentGetOptions{Ref: pre_commit_sha})
			uutil.ErrFatal(err)
			content, err := file_content.GetContent()
			uutil.ErrFatal(err)

			// get funclocatins of target file path
			func_locations, err := goscan.GetFuncLocation(content)
			uutil.ErrFatal(err)

			file_func_locations[file_path] = func_locations
		}
		return file_func_locations, nil
	} else {
		return file_func_locations, xerrors.Errorf("Bug: Strange github url at GetFixedFilesFromPullRequest. '%v'\n", git_url)
	}
}

func (ghop GithubOperation) GetPreCommitFuncLocation(git_url string, file_diffs []FileDiff) (map[string][]gity.FuncLocation, error) {

	file_func_locations := map[string][]gity.FuncLocation{}
	tokens := strings.Split(git_url, "/")

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
		fmt.Printf("WARNING: target commit has %v parents.\n", len(repo_commit.Parents))
		parents := repo_commit.Parents
		for i := 0; i < len(repo_commit.Parents); i++ {
			fmt.Printf("Parent_%v: %v\n", i, parents[i].GetSHA())
		}
	} else if len(repo_commit.Parents) == 0 {
		return map[string][]gity.FuncLocation{}, xerrors.Errorf("Bug: commit don't has the parents commit at GerPreCommitFuncLocation.\n")
	}

	pre_commit_sha := repo_commit.Parents[0].GetSHA()

	for _, file_diff := range file_diffs {
		// get the file content before target commit (use the parent of target commit)
		file_path := file_diff.FilePath
		ctx2, client2 := ghop.NewGithubClient()
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
				start_line := fset.Position(fn.Pos()).Line
				end_line := fset.Position(fn.End()).Line
				func_location := gity.FuncLocation{FuncName: func_name, StartLine: start_line, EndLine: end_line}
				if func_locations, exist := file_func_locations[file_path]; exist {
					func_locations = append(func_locations, func_location)
					file_func_locations[file_path] = func_locations
				} else {
					file_func_locations[file_path] = []gity.FuncLocation{func_location}
				}
			}
		}
	}

	return file_func_locations, nil
}

func (ghop GithubOperation) GetFixedFiles(git_url string) (map[string]bool, error) {
	return map[string]bool{}, xerrors.Errorf("strange github url: %v\n", git_url)
}
