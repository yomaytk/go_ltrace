package gitrepo

import (
	"context"
	"log"
	"os"

	"github.com/google/go-github/v53/github" // with go modules enabled (GO111MODULE=on or outside GOPATH)
	"golang.org/x/oauth2"
)

type GithubOperation struct {
	AuthorName  string
	TokenSource oauth2.TokenSource
}

func NewGithubOperation(author_name string) GitOperation {
	ts := oauth2.StaticTokenSource(
		&oauth2.Token{AccessToken: os.Getenv("GITHUB_ACCESS_TOKEN")},
	)
	return &GithubOperation{AuthorName: author_name, TokenSource: ts}
}

func (ghop *GithubOperation) GetFixedFiles(repo_name string, commit_sha string) []string {
	fixed_files := []string{}

	ctx := context.Background()
	tc := oauth2.NewClient(ctx, ghop.TokenSource)
	client := github.NewClient(tc)

	repo_commit, _, err := client.Repositories.GetCommit(ctx, ghop.AuthorName, repo_name, commit_sha, nil)

	if err != nil {
		log.Fatal(err)
	}

	for _, fixed_file := range repo_commit.Files {
		fixed_files = append(fixed_files, *fixed_file.Filename)
	}

	return fixed_files
}
