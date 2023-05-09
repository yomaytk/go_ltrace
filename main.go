package main

import (
	"fmt"
	"log"
	"os"
	"os/exec"
	"strconv"
	"strings"
)

func err_fatal(err error) {
	if err != nil {
		log.Fatal(err)
	}
}

type CallFunc struct {
	pid    uint32
	symn   string
	rvalue RValue
}

type RValue struct {
	existing bool
	value    string
}

type ParseLtrace struct{}

func (pl ParseLtrace) parse(s string) []CallFunc {
	type CallFuncMapKey struct {
		pid  uint32
		symn string
	}
	lines := strings.Split(s, "\n")
	call_func_map := make(map[CallFuncMapKey]int)
	var call_funcs []CallFunc
	for _, line := range lines {
		// split by space
		tokens := strings.Fields(line)

		if len(tokens) == 0 {
			continue
		}

		// get pid
		pid64, err := strconv.ParseUint(tokens[0], 10, 32)
		if err != nil {
			fmt.Printf("token: %v shouled be convertible to uint.\n", tokens[0])
		}
		pid := uint32(pid64)

		// get function name and return value
		var symn string
		var rvalue RValue
		// resumed
		if strings.Compare(tokens[1], "<...") == 0 && strings.Compare(tokens[3], "resumed>") == 0 {
			symn = tokens[2]
			key := CallFuncMapKey{pid: pid, symn: symn}
			_, exist := call_func_map[key]
			if !exist {
				fmt.Printf("WARNING: call_func_map should have the key of \"%v\".\n", symn)
			} else {
				// delete target key
				delete(call_func_map, key)
			}
			rvalue = RValue{existing: true, value: tokens[len(tokens)-1]}
			// append to call_funcs
			// WARNNING!! current code don't consider the resumed function which don't return value.
			call_funcs = append(call_funcs, CallFunc{pid: pid, symn: symn, rvalue: rvalue})
			continue
		}
		// unfinished
		if strings.Compare(tokens[len(tokens)-1], "...>") == 0 && strings.Compare(tokens[len(tokens)-2], "<unfinished") == 0 {
			symn = tokens[1][0:strings.Index(tokens[1], "(")]
			key := CallFuncMapKey{pid: pid, symn: symn}
			call_func_map[key] = 1
			continue
		}
		// no return
		if strings.Compare(tokens[len(tokens)-1], "...>") == 0 && strings.Compare(tokens[len(tokens)-2], "return") == 0 && strings.Compare(tokens[len(tokens)-3], "<no") == 0 {
			symn = tokens[1][0:strings.Index(tokens[1], "(")]
			call_funcs = append(call_funcs, CallFunc{pid: pid, symn: symn, rvalue: RValue{existing: false, value: ""}})
			continue
		}
		// exit process
		if strings.Compare(tokens[1], "+++") == 0 {
			continue
		}
		// signal
		if strings.Compare(tokens[1], "---") == 0 && strings.HasPrefix(tokens[2], "SIG") {
			continue
		}
		// one line complete function (return value)
		symn = tokens[1][0:strings.Index(tokens[1], "(")]
		rvalue = RValue{existing: true, value: tokens[len(tokens)-1]}
		call_funcs = append(call_funcs, CallFunc{pid: pid, symn: symn, rvalue: rvalue})
	}

	return call_funcs
}

func main() {

	if len(os.Args) != 2 {
		panic("arguments is invalid.\n")
	}

	fmt.Printf("*** ltrace target program: %s ***\n", os.Args[1])

	// -f : trace child process
	cmd := exec.Command("ltrace", "-o", "ltrace_output", "-f", os.Args[1])

	cmd.Stdin = os.Stdin
	cmd.Stdout = os.Stdout

	err_fatal(cmd.Start())
	err_fatal(cmd.Wait())

	// get ltrace output
	content, err := os.ReadFile("ltrace_output")
	err_fatal(err)

	ltrace_s := string(content)
	pl := ParseLtrace{}
	// parse
	call_funcs := ParseLtrace.parse(pl, ltrace_s)
	fmt.Println("=== trace result ===")
	for _, call_func := range call_funcs {
		fmt.Println(call_func)
	}
}
