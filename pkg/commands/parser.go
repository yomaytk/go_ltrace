package commands

import (
	"strconv"
	"strings"

	log "github.com/yomaytk/go_ltrace/log"
	"golang.org/x/xerrors"
)

// ltrace reserved words for parse
const (
	STATE_START_DOTS = "<..."
	RESUMED          = "resumed>"
	STATE_END_DOTS   = "...>"
	UNFINISED        = "<unfinised"
	NO               = "<no"
	RETURN           = "return"
	PPPLUS           = "+++"
	MMMINUS          = "---"
	SIG_PREFIX       = "SIG"
	UNEXPECTED       = "unexpected"
	L_ROUND_BRAC     = "("
	R_ROUND_BRAC     = ")"
)

// strace command global variables and reserved words
const (
	OPENAT = "openat"
	// L_SQUARE_BRAC      = "["
	// R_SQUARE_BRAC      = "]"
)

// file command reserved words for parse
const (
	DYNAMICALLY_LINKED = "dynamically linked"
)

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
