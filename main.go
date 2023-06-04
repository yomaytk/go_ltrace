package main

import (
	"bytes"
	"fmt"
	"os"
	"os/exec"
	"strconv"
	"strings"

	uutil "github.com/yomaytk/go_ltrace/util"
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

type Parser struct{}

func (parser Parser) LtraceParse(s string) (map[pid_t]map[CallFunc]bool, map[string]bool, error) {
	lines := strings.Split(s, "\n")
	no_end_func_map := make(map[CallFuncMapKey]int)
	var pid_and_call_funcs_map = make(map[pid_t]map[CallFunc]bool)
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

func (parser Parser) StraceParse(s string) (map[string]bool, error) {
	lib_map := make(map[string]bool)
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
			lib_map[file_path] = true
			continue
		}

		fmt.Printf("strange line: %v\n", line)
	}

	return lib_map, nil
}

func (parser Parser) DpkgParse(s string) (map[string][]string, error) {

	lines := strings.Split(s, "\n")
	res := map[string][]string{}

	for _, line := range lines {

		// unknown library
		if strings.HasSuffix(line, "dpkg-query: no path") {
			tokens := strings.Fields(line)
			unknown_libs := res["unknown"]
			unknown_libs = append(unknown_libs, tokens[len(tokens)-1])
			res["__unknown"] = unknown_libs
		}

		// ex.) libxdmcp6:arm64: /usr/lib/aarch64-linux-gnu/libXdmcp.so.6
		first_colon_id := strings.Index(line, ":")
		package_name := line[:first_colon_id]
		slash_tokens := strings.Split(line, "/")
		if len(slash_tokens) == 1 {
			return map[string][]string{}, xerrors.Errorf("strange dpkg result\n")
		}
		result_package := slash_tokens[len(slash_tokens)-1] //  -> libXdmcp.so.6
		// don't append similar version package. ex.) libXdmcp.so.6.0.0
		if strings.Compare(package_name, result_package) == 0 {
			libs := res[package_name]
			libs = append(libs, result_package)
			res[package_name] = libs
		} else {
			libs := res["__similar_version"]
			libs = append(libs, result_package)
			res["__similar_version"] = libs
		}
	}

	return res, nil
}

type CommandSet struct {
	parser Parser
}

func (cmds CommandSet) DinamicallyLinked(trace_target []string) bool {
	res, err := exec.Command(CMD_FILE, trace_target...).Output()
	uutil.ErrFatal(err)

	return strings.Contains(string(res), DYNAMICALLY_LINKED)
}

func (cmds CommandSet) Dpkg(lib_map map[string]bool) map[string][]string {

	fmt.Println("[+] Dpkg Start.")

	var used_paths []string = []string{}
	for lib := range lib_map {
		used_paths = append(used_paths, lib)
	}

	// exec dpkg

	s := ""
	err_s := ""
	target_paths := used_paths

	for {

		dpkg_args := append(DPKG_OPTIONS, target_paths...)
		cmd := exec.Command(CMD_DPKG, dpkg_args...)

		// separate stdout and stderr
		var stdout, stderr bytes.Buffer
		cmd.Stdout = &stdout
		cmd.Stderr = &stderr
		cmd.Run()

		// get only files dpkg can find the target package
		s += stdout.String()

		// initialize used_paths
		target_paths = []string{}
		paths_cache := map[string]bool{}

		// search for path one level above
		err_s = stderr.String()
		nohit_lines := strings.Split(err_s, "\n")
		for _, line := range nohit_lines {
			if strings.Compare(line, "") == 0 {
				continue
			}
			nohit_line_tokens := strings.Fields(line)
			nohit_path := nohit_line_tokens[len(nohit_line_tokens)-1]
			last_slash_index := strings.LastIndex(nohit_path, "/")
			next_path := nohit_path[:last_slash_index]
			if len(next_path) > 0 && !paths_cache[next_path] {
				target_paths = append(target_paths, next_path)
				paths_cache[next_path] = true
			}
		}

		if len(target_paths) == 0 {
			break
		}
	}

	fmt.Println(s)
	fmt.Println(err_s)

	// dpkg parse
	// package_lib_map, err2 := cmds.parser.DpkgParse(s)
	// uutil.ErrFatal(err2)

	fmt.Println("[-] Dpkg End.")

	return map[string][]string{}
}

func (cmds CommandSet) Ltrace(trace_target []string) map[string]bool {

	fmt.Println("[+] Ltrace Start.")

	trace_args := append(LTRACE_OPTIONS, trace_target...)
	cmd_ltrace := exec.Command(CMD_LTRACE, trace_args...)
	cmd_ltrace.Stdin = os.Stdin
	cmd_ltrace.Stdout = os.Stdout

	uutil.ErrFatal(cmd_ltrace.Start())
	uutil.ErrFatal(cmd_ltrace.Wait())

	// get ltrace output
	content, err := os.ReadFile(LTARCE_OUTPUT_FILE)
	uutil.ErrFatal(err)

	s := string(content)

	// parse
	_, all_call_funcs_map, err := cmds.parser.LtraceParse(s)
	uutil.ErrFatal(err)

	fmt.Println("[-] Ltrace End.")

	return all_call_funcs_map
}

func (cmds CommandSet) Strace(trace_target []string) map[string]bool {

	fmt.Println("[+] Starce Start.")

	strace_args := append(STRACE_OPTIONS, trace_target...)
	cmd_strace := exec.Command(CMD_STRACE, strace_args...)
	cmd_strace.Stdin = os.Stdin
	cmd_strace.Stdout = os.Stdout

	uutil.ErrFatal(cmd_strace.Start())
	uutil.ErrFatal(cmd_strace.Wait())

	// analyze starce result
	bytes, err := os.ReadFile(STRACE_OUTPUT_FILE)
	uutil.ErrFatal(err)

	s := string(bytes)
	// strace parse
	lib_map, err := cmds.parser.StraceParse(s)

	fmt.Println("[-] Strace End.")

	return lib_map
}

func main() {

	if len(os.Args) < 2 {
		panic("too few arguments.\n")
	}

	target_args := os.Args[1:]
	cmds := CommandSet{parser: Parser{}}

	// trace used shared libraries by "strace"
	if cmds.DinamicallyLinked(target_args) {
		lib_map := cmds.Strace(target_args)
		package_lib_map := cmds.Dpkg(lib_map)
		fmt.Println(package_lib_map)
	}
}
