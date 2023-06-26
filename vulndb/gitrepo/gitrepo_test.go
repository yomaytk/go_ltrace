package gitrepo

import (
	"testing"
)

func TestGithub(t *testing.T) {
	ghop := NewGithubOperation()
	git_url := "https://github.com/yomaytk/go_ltrace/commit/703d447876fa4f044e86fe9ad4e115dfde3f63c0"
	ghop.GetDiffFromCommit(git_url)
}
