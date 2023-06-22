package gitrepo

import (
	"testing"
)

func TestGithub(t *testing.T) {
	ghop := NewGithubOperation()
	git_url := "https://github.com/yomaytk/go_ltrace/commit/bce15e035ca5b37814ae632c81800ce726003234"
	ghop.GetDiffFromCommit(git_url)
}
