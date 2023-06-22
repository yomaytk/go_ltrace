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
