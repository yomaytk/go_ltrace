package commands

import (
	"bytes"
	"fmt"
	"os"
	"os/exec"
	"strings"

	log "github.com/yomaytk/go_ltrace/log"
	ttypes "github.com/yomaytk/go_ltrace/types"
	uutil "github.com/yomaytk/go_ltrace/util"
	"golang.org/x/xerrors"
)

// Linux command
const (
	CMD_LTRACE      = "ltrace"
	CMD_STRACE      = "strace"
	CMD_FILE        = "file"
	CMD_DPKG        = "dpkg"
	CMD_APTCACHE    = "apt-cache"
	CMD_GREP        = "grep"
	CMD_LSB_RELEASE = "lsb_release"
	CMD_GO          = "go"
)

// cache file
const (
	LTARCE_OUTPUT_FILE = "lt_out"
	STRACE_OUTPUT_FILE = "st_out"
	CACHE_DIR          = "$HOME/.cache/"
)

// command options
var LTRACE_OPTIONS = []string{"-o", LTARCE_OUTPUT_FILE, "-f"}
var STRACE_OPTIONS = []string{"-o", STRACE_OUTPUT_FILE, "-s", "1000", "-f", "-e", "trace=openat"}
var DPKG_OPTIONS = []string{"-S"}
var APTSHOW_GREP_OPTIONS = []string{"-E", "Package:|Version:|Source:"}
var APTCACHE_OPTIONS = []string{"show"}
var LSB_RELEASE_OPTIONS = []string{"-a"}

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

func (cmds CommandSet) DynamicallyLinked(trace_target []string) bool {
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
