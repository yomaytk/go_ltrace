package main

import (
	"bytes"
	"fmt"
	"os"
	"os/exec"
	"strconv"
	"strings"

	"github.com/joho/godotenv"
	log "github.com/yomaytk/go_ltrace/log"
	ttypes "github.com/yomaytk/go_ltrace/types"
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

// apt show
const (
	CMD_APTCACHE = "apt-cache"
)

// grep
const (
	CMD_GREP = "grep"
)

const (
	CMD_LSB_RELEASE = "lsb_release"
)

const (
	CACHE_DIR = "$HOME/.cache/"
)

var LTRACE_OPTIONS = []string{"-o", LTARCE_OUTPUT_FILE, "-f"}
var STRACE_OPTIONS = []string{"-o", STRACE_OUTPUT_FILE, "-s", "1000", "-f", "-e", "trace=openat"}
var DPKG_OPTIONS = []string{"-S"}
var APTSHOW_GREP_OPTIONS = []string{"-E", "Package:|Version:|Source:"}
var APTCACHE_OPTIONS = []string{"show"}
var LSB_RELEASE_OPTIONS = []string{"-a"}

type pid_t uint32

type CallFunc struct {
	pid  pid_t
	symn string
}

type CallFuncMapKey struct {
	pid  pid_t
	symn string
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
				log.Logger.Infoln("WARNING: no_end_func_map should have the key of \"%v\".", symn)
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

		log.Logger.Infoln("strange line: %v", line)
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
	OsVersion string
	Parser    Parser
}

func NewCommandSet() *CommandSet {
	cmds := &CommandSet{Parser: Parser{}}
	cmds.getOsVersion()
	return cmds
}

func (cmds *CommandSet) getOsVersion() {

	out, err := exec.Command(CMD_LSB_RELEASE, LSB_RELEASE_OPTIONS...).Output()
	uutil.ErrFatal(err)

	lines := strings.Split(string(out), "\n")

	for _, line := range lines {
		if strings.HasPrefix(line, "Codename:") {
			cmds.OsVersion = strings.Fields(line)[1]
		}
	}
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
		re_search_paths, err := cmds.Parser.DpkgParse(s, package_lib_map, path_cache_map)
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

func (cmds CommandSet) AptShow(package_lib_map map[string][]string) (map[ttypes.PackageDetail][]string, error) {

	fmt.Println("[+] AptShow Start.")

	src_bin_map := map[ttypes.PackageDetail][]string{}
	package_list := []string{}
	for key := range package_lib_map {
		package_list = append(package_list, key)
	}

	// apt-cache show ...
	cmd_args := append(APTCACHE_OPTIONS, package_list...)
	out1, err := exec.Command(CMD_APTCACHE, cmd_args...).Output()
	uutil.ErrFatal(err)

	// | grep -E 'Pacakge:|Source:' ...
	cmd2_args := APTSHOW_GREP_OPTIONS
	cmd2 := exec.Command(CMD_GREP, cmd2_args...)
	cmd2.Stdin = bytes.NewBuffer(out1)

	var stdout, stderr bytes.Buffer
	cmd2.Stdout = &stdout
	cmd2.Stderr = &stderr
	cmd2.Run()

	lines := strings.Split(stdout.String(), "\n")

	for lid := 0; lid < len(lines); {
		pkg_dtl := ttypes.PackageDetail{}
		if strings.Compare(lines[lid], "") == 0 {
			lid++
			continue
		}
		// get package detail
		tokens := strings.Fields(lines[lid])
		if strings.Compare(tokens[0], "Package:") == 0 {
			pkg_dtl.Binaryp = tokens[1]
			pkg_dtl.Sourcep = pkg_dtl.Binaryp
			lid++
			tokens2 := strings.Fields(lines[lid])
			if strings.Compare(lines[lid], "") != 0 && strings.Compare(tokens2[0], "Version:") == 0 {
				pkg_dtl.Version = tokens2[1]
				lid++
			}
			tokens3 := strings.Fields(lines[lid])
			if strings.Compare(lines[lid], "") != 0 && strings.Compare(tokens3[0], "Source:") == 0 {
				pkg_dtl.Sourcep = tokens3[1]
				lid++
			}
			tokens4 := strings.Fields(lines[lid])
			if strings.Compare(lines[lid], "") != 0 && strings.Compare(tokens4[0], "Version:") == 0 {
				pkg_dtl.Version = tokens4[1]
				lid++
			}
		} else {
			return map[ttypes.PackageDetail][]string{}, xerrors.Errorf("Bug: tokens[0]('%v') must be 'Package:'\n", tokens[0])
		}
		src_bin_map[pkg_dtl] = package_lib_map[pkg_dtl.Binaryp]
	}

	if len(stderr.String()) > 0 {
		log.Logger.Infoln("AptShow Error Log: %v", stderr.String())
	}

	fmt.Println("[-] AptShow End.")

	return src_bin_map, nil
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
	_, all_call_funcs_map, err := cmds.Parser.LtraceParse(s)
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
	lib_map, err := cmds.Parser.StraceParse(s)

	fmt.Println("[-] Strace End.")

	return lib_map
}

type Runner struct {
	Uop  *ubuntu.UbuntuOperation
	Cmds *CommandSet
}

func NewRunner(github_author_name string) *Runner {
	cmds := NewCommandSet()
	return &Runner{Uop: ubuntu.NewUbuntuOperation(github_author_name, cmds.OsVersion), Cmds: cmds}
}

func (runner Runner) Run(target_args []string) {

	var ltrace, strace, new_db bool
	ltrace = strings.Compare(os.Getenv("GOSCAN_LTRACE"), "on") == 0
	strace = strings.Compare(os.Getenv("GOSCAN_STRACE"), "on") == 0
	new_db = strings.Compare(os.Getenv("GOSCAN_NEWDB"), "on") == 0

	// construct Initial DB
	if new_db {
		runner.Uop.NewDB()
	}

	// trace the target program at executed time
	if runner.Cmds.DinamicallyLinked(target_args) {

		// using strace (trace only used shared libraries)
		if strace {
			// exec strace to find used shared libraries
			lib_map := runner.Cmds.Strace(target_args)

			// exec dpkg to search the binary package for every shared library
			package_lib_map, err := runner.Cmds.Dpkg(lib_map)
			uutil.ErrFatal(err)

			// exec apt-cache show to search source package for every binary package
			src_bin_map, err := runner.Cmds.AptShow(package_lib_map)
			uutil.ErrFatal(err)
			log.Logger.Infoln("Log: src_bin_map", src_bin_map)
			for key, value := range src_bin_map {
				log.Logger.Infoln("%v: %v", key, value)
			}

			// get target CVEs
			exploitable_cves, err2 := runner.Uop.GetCVEs(src_bin_map)
			uutil.ErrFatal(err2)

			for sourcep, cves := range exploitable_cves {
				fmt.Printf("sourcep: %v\n", sourcep)
				for _, cve := range cves {
					fmt.Printf("%v ", cve.Candidate)
				}
				fmt.Printf("\n")
			}
		}

		// using ltrace (trace coverage of shared libraries)
		if ltrace {
			// TODO
		}

	}

}

func main() {

	// setting env var
	err := godotenv.Load()
	uutil.ErrFatal(err)

	// initialize logger
	log.InitLogger()
	defer log.Logger.Sync()

	if len(os.Args) < 2 {
		panic("too few arguments.\n")
	}

	// run main process
	runner := NewRunner("yomaytk")
	runner.Run(os.Args[1:])
}
