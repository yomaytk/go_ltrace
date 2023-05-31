package main

import (
	"fmt"
	"os"
	"os/exec"
	"strconv"
	"strings"

	uutil "github.com/yomaytk/go_ltrace/util"
	"github.com/yomaytk/go_ltrace/vulndb/ubuntu"
	"golang.org/x/xerrors"
)

// ltrace command global variables and reserved words
const (
	CMD_LTRACE         = "ltrace"
	LTARCE_OUTPUT_FILE = "lt_out"
	STATE_START_DOTS   = "<..."
	RESUMED            = "resumed>"
	STATE_END_DOTS     = "...>"
	UNFINISED          = "<unfinised"
	NO                 = "<no"
	RETURN             = "return"
	PPPLUS             = "+++"
	MMMINUS            = "---"
	SIG_PREFIX         = "SIG"
	UNEXPECTED         = "unexpected"
	L_ROUND_BRAC       = "("
	R_ROUND_BRAC       = ")"
)

// strace command global variables and reserved words
const (
	CMD_STRACE         = "strace"
	STRACE_OUTPUT_FILE = "st_out"
	OPENAT             = "openat"
	// L_SQUARE_BRAC      = "["
	// R_SQUARE_BRAC      = "]"
)

// dynamically linked
const (
	CMD_FILE           = "file"
	DYNAMICALLY_LINKED = "dynamically linked"
)

// dpkg
const (
	CMD_DPKG = "dpkg"
)

const (
	CACHE_DIR = "$HOME/.cache/"
)

var LTRACE_OPTIONS = []string{"-o", LTARCE_OUTPUT_FILE, "-f"}
var STRACE_OPTIONS = []string{"-o", STRACE_OUTPUT_FILE, "-s", "1000", "-f", "-e", "trace=openat"}
var DPKG_OPTIONS = []string{"-S"}

type pid_t uint32
type ltrace_parse_t map[pid_t]map[CallFunc]bool

type CallFunc struct {
	pid  pid_t
	symn string
}

type CallFuncMapKey struct {
	pid  pid_t
	symn string
}

type CVEInfo struct {
	CveDataMeta struct {
		ID       string `json:"ID"`
		Assigner string `json:"ASSIGNER"`
	} `json:"CVE_data_meta"`
	Description struct {
		DescriptionData []struct {
			Lang  string `json:"lang"`
			Value string `json:"value"`
		} `json:"description_data"`
	} `json:"description"`
}

type NvdData struct {
	CveItems []CVEInfo `json:"CVE_Items"`
}

type PackageSet struct {
	tp TraceParser
}

type TraceParser struct{}

func (tp TraceParser) ltraceParse(s string) (ltrace_parse_t, map[string]bool, error) {
	lines := strings.Split(s, "\n")
	no_end_func_map := make(map[CallFuncMapKey]int)
	var pid_and_call_funcs_map = make(ltrace_parse_t)
	var all_call_funcs_map = make(map[string]bool)
	for _, line := range lines[:len(lines)-1] {
		// split by space
		tokens := strings.Fields(line)

		// get pid
		pid64, err := strconv.ParseUint(tokens[0], 10, 32)
		if err != nil {
			return nil, nil, xerrors.Errorf("token: %v shouled be convertible to uint.\n", tokens[0])
		}
		pid := pid_t(pid64)

		// get function name and return value
		var symn string
		var call_func CallFunc

		// resumed
		if strings.Compare(tokens[1], STATE_START_DOTS) == 0 && strings.Compare(tokens[3], RESUMED) == 0 {
			symn = tokens[2]
			key := CallFuncMapKey{pid: pid, symn: symn}
			if _, exist := no_end_func_map[key]; !exist {
				fmt.Printf("WARNING: no_end_func_map should have the key of \"%v\".\n", symn)
			} else {
				// delete target key
				delete(no_end_func_map, key)
			}
			// append to call_funcs
			// WARNNING!! current code don't consider the resumed function which don't return value.
			call_func = CallFunc{pid: pid, symn: symn}
			if call_funcs_map, ok := pid_and_call_funcs_map[pid]; ok {
				call_funcs_map[call_func] = true
			} else {
				pid_and_call_funcs_map[pid] = map[CallFunc]bool{call_func: true}
			}
			all_call_funcs_map[symn] = true
			continue
		}
		// unfinished
		if strings.Compare(tokens[len(tokens)-1], STATE_END_DOTS) == 0 && strings.Compare(tokens[len(tokens)-2], UNFINISED) == 0 {
			symn = tokens[1][0:strings.Index(tokens[1], L_ROUND_BRAC)]
			key := CallFuncMapKey{pid: pid, symn: symn}
			no_end_func_map[key] = 1
			continue
		}
		// no return
		if strings.Compare(tokens[len(tokens)-1], STATE_END_DOTS) == 0 && strings.Compare(tokens[len(tokens)-2], RETURN) == 0 && strings.Compare(tokens[len(tokens)-3], "<no") == 0 {
			symn = tokens[1][0:strings.Index(tokens[1], L_ROUND_BRAC)]
			call_func = CallFunc{pid: pid, symn: symn}
			if call_funcs_map, ok := pid_and_call_funcs_map[pid]; ok {
				call_funcs_map[call_func] = true
			} else {
				pid_and_call_funcs_map[pid] = map[CallFunc]bool{call_func: true}
			}
			all_call_funcs_map[symn] = true
			continue
		}
		// unexpected breakpoint
		if strings.Compare(tokens[1], UNEXPECTED) == 0 {
			continue
		}
		// exit process
		if strings.Compare(tokens[1], PPPLUS) == 0 {
			continue
		}
		// signal
		if strings.Compare(tokens[1], MMMINUS) == 0 && strings.HasPrefix(tokens[2], SIG_PREFIX) {
			continue
		}
		// one line complete function (return value)
		symn = tokens[1][0:strings.Index(tokens[1], L_ROUND_BRAC)]
		call_func = CallFunc{pid: pid, symn: symn}
		if call_funcs_map, ok := pid_and_call_funcs_map[pid]; ok {
			call_funcs_map[call_func] = true
		} else {
			pid_and_call_funcs_map[pid] = make(map[CallFunc]bool)
			pid_and_call_funcs_map[pid][call_func] = true
		}
		all_call_funcs_map[symn] = true
	}

	return pid_and_call_funcs_map, all_call_funcs_map, nil
}

func (tp TraceParser) straceParse(s string) (map[string]bool, error) {
	shared_libraries_map := make(map[string]bool)
	lines := strings.Split(s, "\n")

	for _, line := range lines[:len(lines)-1] {

		// split by space
		tokens := strings.Fields(line)

		// ignore SIGNAL
		if strings.HasPrefix(tokens[1], MMMINUS) || strings.HasPrefix(tokens[1], PPPLUS) {
			continue
		}

		// trace openat function
		if strings.HasPrefix(tokens[1], OPENAT) {
			file_token := tokens[2]
			// ignore unknown memory address of second arugment about openat function
			if strings.HasPrefix(file_token, "0x") {
				continue
			}
			file_path := file_token[1 : len(file_token)-2]
			shared_libraries_map[file_path] = true
			continue
		}

		fmt.Printf("strange line: %v\n", line)
	}

	return shared_libraries_map, nil
}

func (ps PackageSet) collectTargetPackages() (map[string][]string, error) {
	content, err := os.ReadFile(STRACE_OUTPUT_FILE)
	uutil.ErrFatal(err)

	strace_s := string(content)
	// strace parse
	shared_libraries_map, err := ps.tp.straceParse(strace_s)

	var shared_libraries []string
	for shared_library := range shared_libraries_map {
		shared_libraries = append(shared_libraries, shared_library)
	}

	fmt.Println(shared_libraries)

	dpkg_args := append(DPKG_OPTIONS, shared_libraries...)
	res, err := exec.Command(CMD_DPKG, dpkg_args...).Output()

	// parse dpkg
	lines := strings.Split(string(res), "\n")
	// for _, line := range lines {
	// 	tokens := strings.Fields(line)

	// }
	for _, line := range lines {
		fmt.Printf("line: %v\n", line)
	}

	return nil, nil
}

func main() {

	if len(os.Args) < 2 {
		panic("too few arguments.\n")
	}

	tp := TraceParser{}

	uop := ubuntu.UbuntuOperation{PackagesForQuery: map[ubuntu.UbuntuPackage]ubuntu.PackageCVEs{}, UbuntuCVEs: []ubuntu.UbuntuCVE{}}
	uop.CollectCVEs()

	// // Open the my.db data file in your current directory.
	// // It will be created if it doesn't exist.
	// db, err := bolt.Open("cve.db", 0600, nil)
	// uutil.ErrFatal(err)
	// defer db.Close()

	res, err := exec.Command(CMD_FILE, os.Args[1:]...).Output()
	uutil.ErrFatal(err)

	// ltrace if target binary is dynamically linked
	if strings.Contains(string(res), DYNAMICALLY_LINKED) {

		fmt.Printf("target is dynamically linked.\n")
		ps := PackageSet{tp: TraceParser{}}

		// ltrace
		trace_args := append(LTRACE_OPTIONS, os.Args[1:]...)
		cmd_ltrace := exec.Command(CMD_LTRACE, trace_args...)

		cmd_ltrace.Stdin = os.Stdin
		cmd_ltrace.Stdout = os.Stdout

		uutil.ErrFatal(cmd_ltrace.Start())
		uutil.ErrFatal(cmd_ltrace.Wait())

		// get ltrace output
		content, err := os.ReadFile(LTARCE_OUTPUT_FILE)
		uutil.ErrFatal(err)

		ltrace_s := string(content)
		// ltraceParse
		pid_and_call_funcs_map, all_call_funcs_map, err := TraceParser.ltraceParse(tp, ltrace_s)
		uutil.ErrFatal(err)

		fmt.Println("=== trace result ===")
		for key_pid, call_funcs_map := range pid_and_call_funcs_map {
			fmt.Printf("[PID: %v]\n", key_pid)
			for call_func := range call_funcs_map {
				fmt.Println(call_func)
			}
		}
		i := 0
		for call_func := range all_call_funcs_map {
			fmt.Printf("func_%v: %v\n", i, call_func)
			i++
		}

		// strace
		strace_args := append(STRACE_OPTIONS, os.Args[1:]...)
		cmd_strace := exec.Command(CMD_STRACE, strace_args...)

		cmd_strace.Stdin = os.Stdin
		cmd_strace.Stdout = os.Stdout

		uutil.ErrFatal(cmd_strace.Start())
		uutil.ErrFatal(cmd_strace.Wait())

		ps.collectTargetPackages()
	}

}
