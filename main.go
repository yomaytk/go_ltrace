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

	lib_map := map[string]bool{}
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

func (parser Parser) DpkgParse(s string, package_lib_map map[string][]string, path_cache_map map[string][]string) ([]string, error) {

	lines := strings.Split(s, "\n")
	re_search_paths := []string{}

	for _, line := range lines {

		if strings.Compare(line, "") == 0 {
			continue
		}

		// must not parse unknown library
		if strings.HasSuffix(line, "dpkg-query: no path") {
			return []string{}, xerrors.Errorf("Bug: must not parse unknown library.\n")
		}

		// cannot specify unit package, so search again (/lib/* -> /usr/lib/*)
		first_comma_id := strings.Index(line, ",")
		if first_comma_id != -1 {
			tokens := strings.Fields(line)
			target_path := tokens[len(tokens)-1]
			if strings.Compare(target_path, "/usr") != 0 && strings.Compare(target_path, "/etc") != 0 {
				re_search_paths = append(re_search_paths, target_path)
			}
			continue
		}

		// ex.) libxdmcp6:arm64: /usr/lib/aarch64-linux-gnu/libXdmcp.so.6
		first_colon_id := strings.Index(line, ":")
		package_name := line[:first_colon_id]
		tokens := strings.Fields(line)
		target_path := tokens[len(tokens)-1]
		target_original_paths := path_cache_map[target_path]
		if paths, ok := package_lib_map[package_name]; ok {
			paths = append(paths, target_original_paths...)
			package_lib_map[package_name] = paths
		} else {
			package_lib_map[package_name] = target_original_paths
		}
	}

	return re_search_paths, nil
}

type CommandSet struct {
	parser Parser
}

func (cmds CommandSet) DinamicallyLinked(trace_target []string) bool {
	res, err := exec.Command(CMD_FILE, trace_target...).Output()
	uutil.ErrFatal(err)

	return strings.Contains(string(res), DYNAMICALLY_LINKED)
}

func (cmds CommandSet) Dpkg(lib_map map[string]bool) (map[string][]string, error) {

	fmt.Println("[+] Dpkg Start.")

	package_lib_map := map[string][]string{}
	var used_paths []string = []string{}
	path_cache_map := map[string][]string{}

	for lib := range lib_map {
		used_paths = append(used_paths, lib)
		path_cache_map[lib] = []string{lib}
	}

	// exec dpkg
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
		s := stdout.String()
		re_search_paths, err := cmds.parser.DpkgParse(s, package_lib_map, path_cache_map)
		uutil.ErrFatal(err)

		// add re_search_paths
		target_paths = []string{}
		for _, re_search_path := range re_search_paths {
			if re_search_original_paths, ok := path_cache_map[re_search_path]; ok {
				// /lib/... -> /usr/lib/...
				for _, original_path := range re_search_original_paths {
					usr_original_path := "/usr" + original_path
					target_paths = append(target_paths, usr_original_path)
					// update path_cache_map
					path_cache_map[usr_original_path] = []string{original_path}
				}
				delete(path_cache_map, re_search_path)
			} else {
				return map[string][]string{}, xerrors.Errorf("Bug: re_search_target_paths must not be empty.\n")
			}
		}

		multiple_path_map := map[string]bool{}
		err_s := stderr.String()
		nohit_lines := strings.Split(err_s, "\n")

		for _, line := range nohit_lines {
			if strings.Compare(line, "") == 0 {
				continue
			}
			nohit_line_tokens := strings.Fields(line)
			nohit_path := nohit_line_tokens[len(nohit_line_tokens)-1]
			last_slash_index := strings.LastIndex(nohit_path, "/")
			if last_slash_index == -1 {
				continue
			}
			next_path := nohit_path[:last_slash_index]
			// append path one level above
			if len(next_path) > 0 && !multiple_path_map[next_path] {
				target_paths = append(target_paths, next_path)
				multiple_path_map[next_path] = true
			}
			// update path_cache_map
			nohit_original_paths := path_cache_map[nohit_path]
			if target_original_paths, ok := path_cache_map[next_path]; ok {
				target_original_paths = append(target_original_paths, nohit_original_paths...)
				path_cache_map[next_path] = target_original_paths
			} else {
				path_cache_map[next_path] = nohit_original_paths
			}
			delete(path_cache_map, nohit_path)
		}

		if len(target_paths) == 0 {
			// TODO: error for logger
			break
		}
	}

	fmt.Println("[-] Dpkg End.")

	return package_lib_map, nil
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
		package_lib_map, err := cmds.Dpkg(lib_map)
		uutil.ErrFatal(err)
		cnt := 0
		for key, value := range package_lib_map {
			cnt += len(value)
			fmt.Printf("%v: %v\n", key, value)
		}
		fmt.Printf("file count: %v\n", cnt)
	}
}
