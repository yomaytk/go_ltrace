package commands

type pid_t uint32

type CallFunc struct {
	pid  pid_t
	symn string
}

type CallFuncMapKey struct {
	pid  pid_t
	symn string
}

type FuncCoverage struct {
	PackageName string
	Path        string
	FuncLine    int
	FuncName    string
	Coverage    string
}

func NewFuncCoverage(package_name string, path string, func_line int, func_name string, coverage string) *FuncCoverage {
	return &FuncCoverage{PackageName: package_name, Path: path, FuncLine: func_line, FuncName: func_name, Coverage: coverage}
}
