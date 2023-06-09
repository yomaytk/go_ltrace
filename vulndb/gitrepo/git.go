package gitrepo

type GitOperation interface {
	GetFixedFiles(repo_name string, commit_sha string) []string
}
