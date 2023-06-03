package ubuntu

import (
	"fmt"
	"io/ioutil"
	"reflect"
	"regexp"
	"strings"

	uutil "github.com/yomaytk/go_ltrace/util"
	types "github.com/yomaytk/go_ltrace/vulndb"
	"golang.org/x/xerrors"
)

const (
	UBUNTU_SRC_PATH = "vulnsrc/ubuntu/ubuntu-cve-tracker/active/"
)

const (
	UNTRIAGED priority_t = iota
	NEGLIGIBLE
	LOW
	MEDIUM
	HIGH
	CRITICAL
)

var meta_data_item_map = map[string]bool{"PublicDateAtUSN": true, "Candidate": true, "PublicDate": true, "References": true,
	"Description": true, "Ubuntu-Description": true, "Notes": true, "Mitigation": true, "Bugs": true, "Priority": true,
	"Discovered-by": true, "Assigned-to": true, "CVSS": true}

var all_support_versions = map[string]bool{"esm": true, "esm-apps": true, "esm-infra": true,
	"stable-phone-overlay": true, "ubuntu-core": true, "fips": true, "fips-updates": true, "ros-esm": true}

var all_ubuntu_distrs = map[string]bool{"warty": true, "hoary": true, "breezy": true, "dapper": true, "edgy": true,
	"feisty": true, "gutsy": true, "hardy": true, "intrepid": true, "jaunty": true, "karmic": true, "lucid": true,
	"maverick": true, "Natty": true, "oneiric": true, "precise": true, "quantal": true, "raring": true, "saucy": true,
	"trusty": true, "utopic": true, "vivid": true, "wily": true, "xenial": true, "yakkety": true, "zesty": true, "artful": true,
	"bionic": true, "cosmic": true, "disco": true, "eoan": true, "focal": true, "groovy": true,
	"hirsute": true, "jammy": true, "kinetic": true, "lunar": true, "devel": true}

type UbuntuPackages map[string]UbuntuPackage
type priority_t uint8
type PatchData string

type UbuntuVersion struct {
	Distr          string `json:"distr"`
	SpecialSupport string `json:"special_support"`
}

type PackageCVEs struct {
	UbuntuPackage `json:"ubuntu_package"`
	CVEIds        []string `json:"cve_id"`
}

type UbuntuCVE struct {
	types.CVE         `json:"CVE"`
	PublicDateAtUSN   string                      `json:"public_date_at_usn"`
	PublicDate        string                      `json:"public_date"`
	References        string                      `json:"references"`
	UbuntuDescription string                      `json:"ubuntu_description"`
	Notes             string                      `json:"notes"`
	Mitigation        string                      `json:"mitigation"`
	Bugs              string                      `json:"bugs"`
	DiscoveredBy      string                      `json:"discovered_by"`
	AssignedTo        string                      `json:"assigned_to"`
	Patches           map[UbuntuPackage]PatchData `json:"patches"`
}

type UbuntuPackage struct {
	UbuntuVersion `json:"ubuntu_version"`
	PackageName   string `json:"package_name"`
}

type UbuntuOperation struct {
	PackagesForQuery map[UbuntuPackage]PackageCVEs `json:"packages_for_query"`
	UbuntuCVEs       []UbuntuCVE                   `json:"ubuntu_cves"`
}

type UbuntuCveParser struct{}

func (uop *UbuntuOperation) CollectCVEs() {
	fmt.Println("[+] Collect Ubuntu CVEs Start.")
	files, err := ioutil.ReadDir(UBUNTU_SRC_PATH)
	uutil.ErrFatal(err)
	ucp := UbuntuCveParser{}

	for _, file := range files {
		if strings.HasPrefix(file.Name(), "CVE") {
			data, err := ioutil.ReadFile(UBUNTU_SRC_PATH + file.Name())
			uutil.ErrFatal(err)
			err2 := ucp.Parse(string(data), uop)
			uutil.ErrFatal(err2)
		}
	}
	fmt.Println("[-] Collect Ubuntu CVEs End.")
}

func (ucp UbuntuCveParser) GetOneItemOnMetaData(lines []string, id *int) (string, string, error) {
	content := ""
	colon_id := strings.Index(lines[*id], ":")
	target_item := lines[*id][:colon_id]

	if !meta_data_item_map[target_item] {
		return "", "", xerrors.Errorf("Bug: GetOneItemOnMetaData first token parse failed. target_item: %v\n", target_item)
	}

	// include content in the same line of target_item
	if colon_id < len(lines[*id]) {
		content += lines[*id][colon_id:]
	}

	*id++

	for {
		first_colon_id := strings.Index(lines[*id], ":")
		if first_colon_id != -1 {
			ss := lines[*id][:first_colon_id]
			if meta_data_item_map[ss] || (strings.HasPrefix(ss, "Patches_") || strings.HasPrefix(ss, "Tags_")) {
				break
			}
		}
		content += "\n" + lines[*id]
		*id++
	}

	return target_item, content, nil
}

func (ucp UbuntuCveParser) Parse(s string, uop *UbuntuOperation) error {

	ubuntu_cve := UbuntuCVE{Patches: map[UbuntuPackage]PatchData{}}
	lines := strings.Split(s, "\n")
	patch_start_id := 0

	// get meta data
	ubuntu_cve_elems := reflect.ValueOf(&ubuntu_cve).Elem()
	line_id := 0

	for {
		// for CVE-2020-5504
		if strings.Compare(lines[line_id], "") == 0 {
			line_id++
			patch_start_id++
			continue
		}

		// get the content for target_item
		target_item, content, err := ucp.GetOneItemOnMetaData(lines, &line_id)
		uutil.ErrFatal(err)

		// convert target item for UbuntuCVE field name ex.) Discovered-by -> DiscoveredBy
		target_item_words := strings.Split(target_item, "-")
		for i, word := range target_item_words {
			target_item_words[i] = strings.Title(word)
		}
		target_item_for_elem := strings.Join(target_item_words, "")

		// set target field
		field := ubuntu_cve_elems.FieldByName(target_item_for_elem)
		if field.IsValid() && field.CanSet() {
			field.SetString(content)
		} else {
			return xerrors.Errorf("Bug: failed to ubuntu_cve_elems.FieldByName(%v)\n", target_item_for_elem)
		}

		if strings.Compare(target_item, "CVSS") == 0 {
			break
		}
	}

	for i := 0; i < line_id; i++ {
		patch_start_id += len(lines[i]) + 1 // add '\n'
	}

	block_re := regexp.MustCompile("\n{2,}")
	patch_start_s := s[patch_start_id:]
	patch_blocks := block_re.Split(patch_start_s, -1)

	// get patches data
	for _, block := range patch_blocks {
		var ubuntu_package UbuntuPackage

		lines := strings.Split(block, "\n")
		if strings.Index(lines[0], ":") == -1 {
			continue
		}

		package_part := lines[0][:strings.Index(lines[0], ":")]
		ubuntu_package.PackageName = package_part[strings.Index(package_part, "_")+1:]

		// get affected packages for every ubuntu version
		for _, line := range lines[1:] {
			var ubuntu_version UbuntuVersion
			// ex. words: ["lucid_gcc-4.1:", "ignored", "(reached", "end-of-life)"]
			package_and_patch := strings.Fields(line)
			if len(package_and_patch) == 0 {
				break
			}
			package_words := strings.Split(package_and_patch[0], "/")

			// read package data
			if words_len := len(package_words); words_len == 1 {
				// don't include "/"
				// ex. words2: ["trusty", "seahorse"]
				package_words2 := strings.Split(package_words[0], "_")
				ubuntu_version = UbuntuVersion{Distr: package_words2[0], SpecialSupport: ""}
			} else if words_len == 2 {
				package_words2 := strings.Split(package_words[1], "_")
				// ESM support
				if all_support_versions[package_words[0]] {
					ubuntu_version = UbuntuVersion{Distr: package_words2[0], SpecialSupport: package_words[0]}
				} else if all_ubuntu_distrs[package_words[0]] {
					if !all_support_versions[package_words2[0]] {
						return xerrors.Errorf("Bug: cannot Parse specific ubuntu support.\n")
					}
					ubuntu_version = UbuntuVersion{Distr: package_words[0], SpecialSupport: package_words2[0]}
				} else if strings.HasPrefix(package_words[0], "Priority") {
					// ignore the exploitability for the specific package in current design
					continue
				} else {
					return xerrors.Errorf("Bug: cannot parse special support. target: %v\n", package_words[0])
				}
			} else if words_len > 2 {
				return xerrors.Errorf("Bug: words_len > 2 error. words: %v\n", package_words)
			}

			ubuntu_package.UbuntuVersion = ubuntu_version

			// read patch data
			patch_words := package_and_patch[1:]
			patch_data := strings.Join(patch_words, " ")
			ubuntu_cve.Patches[ubuntu_package] = PatchData(patch_data)

			// update PackagesForQuery
			if package_cves, ok := uop.PackagesForQuery[ubuntu_package]; !ok {
				package_cves = PackageCVEs{UbuntuPackage: ubuntu_package, CVEIds: []string{ubuntu_cve.Candidate}}
				uop.PackagesForQuery[ubuntu_package] = package_cves
			} else {
				package_cves.CVEIds = append(package_cves.CVEIds, ubuntu_cve.Candidate)
				uop.PackagesForQuery[ubuntu_package] = package_cves
			}

		}
	}
	// update UbuntuCVEs
	uop.UbuntuCVEs = append(uop.UbuntuCVEs, ubuntu_cve)

	return nil
}
