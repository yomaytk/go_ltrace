package main

import (
	"fmt"
	"os"
	"strings"

	"github.com/joho/godotenv"
	"github.com/yomaytk/go_ltrace/log"
	"github.com/yomaytk/go_ltrace/pkg/commands"
	uutil "github.com/yomaytk/go_ltrace/util"
	"github.com/yomaytk/go_ltrace/vulndb/ubuntu"
)

type Runner struct {
	Uop  *ubuntu.UbuntuOperation
	Cmds *commands.CommandSet
}

func NewRunner(github_author_name string) *Runner {
	cmds := commands.NewCommandSet()
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
	if runner.Cmds.DynamicallyLinked(target_args) {

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
