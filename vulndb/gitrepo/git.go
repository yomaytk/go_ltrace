package gitrepo

type GitOperation interface {
	GetFixedFiles(git_url string) (map[string]bool, error)
}
