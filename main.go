package main

import (
	"encoding/json"
	"fmt"
	"log"
	"net/http"
	"os"
	"os/exec"
	"strconv"
	"strings"

	"github.com/boltdb/bolt"
	"golang.org/x/xerrors"
)

// ltrace command global variables and reserved words
const (
	CMD_LTRACE         = "ltrace"
	LTARCE_OUTPUT_FILE = "l_out"
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
	L_BRAC             = "("
	R_BRAC             = ")"
)

// dynamically linked
const (
	CMD_FILE           = "file"
	DYNAMICALLY_LINKED = "dynamically linked"
)

var LTRACE_OPTIONS = []string{"-o", LTARCE_OUTPUT_FILE, "-f"}

func err_fatal(err error) {
	if err != nil {
		log.Fatal(err)
	}
}

type pid_t uint32
type ltrace_parse_t map[pid_t]map[CallFunc]bool

type CallFunc struct {
	pid  pid_t
	symn string
	// rvalue RValue
}

// type RValue struct {
// 	existing bool
// 	value    string
// }

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

type ParseLtrace struct{}

func (pl ParseLtrace) parse(s string) (ltrace_parse_t, map[string]bool, error) {
	lines := strings.Split(s, "\n")
	no_end_func_map := make(map[CallFuncMapKey]int)
	var pid_and_call_funcs_map = make(ltrace_parse_t)
	var all_call_funcs_map = make(map[string]bool)
	for _, line := range lines {
		// split by space
		tokens := strings.Fields(line)

		if len(tokens) == 0 {
			continue
		}

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
			symn = tokens[1][0:strings.Index(tokens[1], L_BRAC)]
			key := CallFuncMapKey{pid: pid, symn: symn}
			no_end_func_map[key] = 1
			continue
		}
		// no return
		if strings.Compare(tokens[len(tokens)-1], STATE_END_DOTS) == 0 && strings.Compare(tokens[len(tokens)-2], RETURN) == 0 && strings.Compare(tokens[len(tokens)-3], "<no") == 0 {
			symn = tokens[1][0:strings.Index(tokens[1], L_BRAC)]
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
		symn = tokens[1][0:strings.Index(tokens[1], L_BRAC)]
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

func getOneCVE() (NvdData, error) {
	url := "https://services.nvd.nist.gov/rest/json/cves/1.0?resultsPerPage=1"

	resp, err := http.Get(url)
	err_fatal(err)
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		return NvdData{}, xerrors.Errorf("unexpected HTTP status:", resp.Status)
	}

	var nvd_data NvdData
	if err := json.NewDecoder(resp.Body).Decode(&nvd_data); err != nil {
		return NvdData{}, xerrors.Errorf("error: ", err)
	}

	return nvd_data, nil
}

func main() {

	if len(os.Args) < 2 {
		panic("too few arguments.\n")
	}

	// vulnerability DB operation
	nvd_data, err := getOneCVE()
	err_fatal(err)

	for _, item := range nvd_data.CveItems {
		fmt.Println("CVE ID:", item.CveDataMeta.ID)
		fmt.Println("Assigner:", item.CveDataMeta.Assigner)
		for _, desc := range item.Description.DescriptionData {
			fmt.Println("Description:", desc.Value)
		}
	}

	// Open the my.db data file in your current directory.
	// It will be created if it doesn't exist.
	db, err := bolt.Open("cve.db", 0600, nil)
	err_fatal(err)
	defer db.Close()

	res1, err := exec.Command(CMD_FILE, os.Args[1:]...).Output()
	err_fatal(err)

	// ltrace if target binary is dynamically linked
	if strings.Contains(string(res1), DYNAMICALLY_LINKED) {

		fmt.Printf("target is dynamically linked.\n")

		// -f : trace child process
		trace_args := append(LTRACE_OPTIONS, os.Args[1:]...)
		cmd_ltrace := exec.Command(CMD_LTRACE, trace_args...)

		cmd_ltrace.Stdin = os.Stdin
		cmd_ltrace.Stdout = os.Stdout

		err_fatal(cmd_ltrace.Start())
		err_fatal(cmd_ltrace.Wait())

		// get ltrace output
		content, err := os.ReadFile(LTARCE_OUTPUT_FILE)
		err_fatal(err)

		ltrace_s := string(content)
		pl := ParseLtrace{}
		// parse
		pid_and_call_funcs_map, all_call_funcs_map, err := ParseLtrace.parse(pl, ltrace_s)
		err_fatal(err)

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
	}

}
