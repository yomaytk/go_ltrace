package ubuntu

import (
	"fmt"
	"io/ioutil"
	"os"
	"reflect"
	"regexp"
	"strings"

	jsoniter "github.com/json-iterator/go"

	log "github.com/yomaytk/go_ltrace/log"
	ttypes "github.com/yomaytk/go_ltrace/types"
	uutil "github.com/yomaytk/go_ltrace/util"
	types "github.com/yomaytk/go_ltrace/vulndb"
	git "github.com/yomaytk/go_ltrace/vulndb/gitrepo"
	"go.etcd.io/bbolt"
	"golang.org/x/xerrors"
)

const (
	UBUNTU_SRC_PATH   = "vulnsrc/ubuntu/ubuntu-cve-tracker/active/"
	VULNDB            = "./cache/VulnDB"
	CVE_TABLE         = "UbuntuCVE"
	CVE_PACKAGE_TABLE = "CVEForPackage"
)

var meta_data_item_map = map[string]bool{"PublicDateAtUSN": true, "Candidate": true, "PublicDate": true, "CRD": true, "References": true,
	"Description": true, "Ubuntu-Description": true, "Notes": true, "Mitigation": true, "Bugs": true, "Priority": true,
	"Discovered-by": true, "Assigned-to": true, "CVSS": true}

var all_support_versions = map[string]bool{"esm": true, "esm-apps": true, "esm-infra": true,
	"stable-phone-overlay": true, "ubuntu-core": true, "fips": true, "fips-updates": true, "ros-esm": true}

var package_env = map[string]bool{"warty": true, "hoary": true, "breezy": true, "dapper": true, "edgy": true,
	"feisty": true, "gutsy": true, "hardy": true, "intrepid": true, "jaunty": true, "karmic": true, "lucid": true,
	"maverick": true, "Natty": true, "oneiric": true, "precise": true, "quantal": true, "raring": true, "saucy": true,
	"trusty": true, "utopic": true, "vivid": true, "wily": true, "xenial": true, "yakkety": true, "zesty": true, "artful": true,
	"bionic": true, "cosmic": true, "disco": true, "eoan": true, "focal": true, "groovy": true, "natty": true,
	"hirsute": true, "jammy": true, "kinetic": true, "impish": true, "lunar": true, "devel": true, "upstream": true}

var package_manager = map[string]bool{"snap": true}

type UbuntuVersion string // os_version@special_support

func NewUbuntuVersion(os_version string, special_support string) UbuntuVersion {
	return UbuntuVersion(os_version + "@" + special_support)
}

type PatchData struct {
	DiffURLs           []string                            `json:"upstream_urls"`
	SpecificPatchDatas map[UbuntuVersion]SpecificPatchData `json:"specific_patch_datas"`
}

type SpecificPatchData struct {
	Affected string `json:"affected"`
	SubInfo  string `json:"sub_info"`
}

type UbuntuCVE struct {
	types.CVE         `json:"CVE"`
	PublicDateAtUSN   string               `json:"public_date_at_usn"`
	PublicDate        string               `json:"public_date"`
	CRD               string               `json:"crd"`
	References        string               `json:"references"`
	UbuntuDescription string               `json:"ubuntu_description"`
	Notes             string               `json:"notes"`
	Mitigation        string               `json:"mitigation"`
	Bugs              string               `json:"bugs"`
	DiscoveredBy      string               `json:"discovered_by"`
	AssignedTo        string               `json:"assigned_to"`
	Patches           map[string]PatchData `json:"patches"` // map[package_name]PatchData
}

type PackageCVERefs struct {
	PackageName string   `json:"package_name"`
	CVEIds      []string `json:"cve_id"`
}

type CVEParser struct{}

type UbuntuOperation struct {
	OsVersion string
	*DBOperation
	*QueryOperation
}

func NewUbuntuOperation(author_name string, os_version string) *UbuntuOperation {
	return &UbuntuOperation{OsVersion: os_version, DBOperation: NewDBOperation(author_name), QueryOperation: NewQueryOperation(os_version)}
}

func (uop *UbuntuOperation) GetCVEs(src_bin_map map[ttypes.PackageDetail][]string) (map[string][]UbuntuCVE, error) {
	src_cves_map := uop.QueryOperation.GetTargetCVEs(src_bin_map)
	exploitable_cves, err := uop.QueryOperation.GetCVEExploitability(src_bin_map, src_cves_map)
	uutil.ErrFatal(err)
	return exploitable_cves, nil
}

type QueryOperation struct {
	OsVersion    string
	GitOperation git.GitOperation
}

func NewQueryOperation(os_version string) *QueryOperation {
	return &QueryOperation{OsVersion: os_version, GitOperation: git.NewGithubOperation(os.Getenv("GITHUB_AUTHOR"))}
}

func (qop *QueryOperation) GetTargetCVEs(src_bin_map map[ttypes.PackageDetail][]string) map[ttypes.PackageDetail][]UbuntuCVE {

	src_cves_map := map[ttypes.PackageDetail][]UbuntuCVE{}
	db, err := bbolt.Open(VULNDB, 0600, nil)
	uutil.ErrFatal(err)
	json := jsoniter.ConfigCompatibleWithStandardLibrary

	// get target CVEs for every source package
	src_and_cveids := map[ttypes.PackageDetail][]string{}
	err = db.View(func(tx *bbolt.Tx) error {

		b := tx.Bucket([]byte(CVE_PACKAGE_TABLE))
		if b == nil {
			return xerrors.Errorf("Cannot find %v.\n", CVE_PACKAGE_TABLE)
		}

		for key := range src_bin_map {
			// get target cve ids
			var cveids []string
			data := b.Get([]byte(key.Sourcep))
			if data == nil {
				log.Logger.Infoln("%v don't have vulnelability.\n", key.Sourcep)
				continue
			}
			err := json.Unmarshal(data, &cveids)
			uutil.ErrFatal(err)
			src_and_cveids[key] = cveids
		}

		return nil
	})
	uutil.ErrFatal(err)

	// get target cves
	for src, cveids := range src_and_cveids {
		err := db.View(func(tx *bbolt.Tx) error {

			b := tx.Bucket([]byte(CVE_TABLE))
			if b == nil {
				return xerrors.Errorf("Cannot find %v. second \n", CVE_PACKAGE_TABLE)
			}

			cves := []UbuntuCVE{}
			// get CVEs for every target package
			for _, cveid := range cveids {
				var cve UbuntuCVE
				data := b.Get([]byte(cveid))
				err := json.Unmarshal(data, &cve)
				uutil.ErrFatal(err)
				cves = append(cves, cve)
			}
			src_cves_map[src] = cves

			return nil
		})
		uutil.ErrFatal(err)
	}

	return src_cves_map
}

func (qop *QueryOperation) GetCVEExploitability(src_bin_map map[ttypes.PackageDetail][]string, src_cves_map map[ttypes.PackageDetail][]UbuntuCVE) (map[string][]UbuntuCVE, error) {

	fmt.Println("[+] GetCVEExploitability Start.")

	// key: sourcep, value: ubuntu_cves
	exploitable_cves := map[string][]UbuntuCVE{}

	// key: sourcep, value: shared_libraries
	src_files_map := map[string][]string{}
	for package_detail, target_files := range src_bin_map {
		if files, ok := src_files_map[package_detail.Sourcep]; ok {
			files = append(files, target_files...)
			src_files_map[package_detail.Sourcep] = files
		} else {
			src_files_map[package_detail.Sourcep] = target_files
		}
	}

	for package_detail, cves := range src_cves_map {

		sourcep := package_detail.Sourcep
		// ignore ESM support in current design
		ubuntu_version := NewUbuntuVersion(qop.OsVersion, "")

		for _, cve := range cves {
			target_patches := cve.Patches[sourcep]
			// the patch for target OsVersion doesn't exist.
			var specific_patch_data SpecificPatchData
			if value, ok := target_patches.SpecificPatchDatas[ubuntu_version]; ok {
				specific_patch_data = value
			} else {
				continue
			}
			affected := specific_patch_data.Affected
			// this cve is not affected
			if strings.Compare(affected, "DNE") == 0 || strings.Compare(affected, "not-affected") == 0 {
				continue
			}
			// if patch is not public, we consider this cve is affected
			if len(target_patches.DiffURLs) == 0 {
				if ex_cves, ok := exploitable_cves[sourcep]; ok {
					ex_cves = append(ex_cves, cve)
					exploitable_cves[sourcep] = ex_cves
				} else {
					exploitable_cves[sourcep] = []UbuntuCVE{cve}
				}
				continue
			}
			// get the fixed files of patch
			fixed_files := map[string]bool{}
			for _, diff_url := range target_patches.DiffURLs {
				if strings.Contains(diff_url, "github.com") {
					new_fixed_files, err := qop.GitOperation.GetFixedFiles(diff_url)
					for new_fixed_file, _ := range new_fixed_files {
						fixed_files[new_fixed_file] = true
					}
					uutil.ErrFatal(err)
					log.Logger.Infoln("source: %v", sourcep)
					log.Logger.Infow("fixed_files", fixed_files)
				}
			}
			// compare the used files to fixed files
			used_files := src_files_map[sourcep]
			for _, used_file := range used_files {
				for fixed_file, _ := range fixed_files {
					// used file is fixed
					if strings.Contains(used_file, fixed_file) {
						if cves, ok := exploitable_cves[sourcep]; ok {
							cves = append(cves, cve)
							exploitable_cves[sourcep] = cves
						} else {
							exploitable_cves[sourcep] = []UbuntuCVE{cve}
						}
						break
					}
				}
			}
		}
	}

	fmt.Println("[+] GetCVEExploitability End.")

	return exploitable_cves, nil
}

type DBOperation struct {
	CVEsForPackage map[string][]string `json:"packages_for_query"`
	UbuntuCVEs     []UbuntuCVE         `json:"ubuntu_cves"`
}

func NewDBOperation(author_name string) *DBOperation {
	return &DBOperation{CVEsForPackage: map[string][]string{}, UbuntuCVEs: []UbuntuCVE{}}
}

func (uop *DBOperation) CollectCVEs() {

	fmt.Println("[+] Collect Ubuntu CVEs Start.")
	files, err := ioutil.ReadDir(UBUNTU_SRC_PATH)
	uutil.ErrFatal(err)
	ucp := CVEParser{}

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

func (uop *DBOperation) NewDB() {

	fmt.Println("[+] Ubuntu NewDB Start.")
	json := jsoniter.ConfigCompatibleWithStandardLibrary

	// collect CVE information from ubuntu-cve-tracker
	uop.CollectCVEs()

	db, err := bbolt.Open(VULNDB, 0600, nil)
	uutil.ErrFatal(err)
	defer db.Close()

	// save all Ubuntu CVE
	err = db.Update(func(tx *bbolt.Tx) error {
		b, err := tx.CreateBucketIfNotExists([]byte(CVE_TABLE))
		uutil.ErrFatal(err)

		for _, ubuntu_cve := range uop.UbuntuCVEs {

			// key and value
			key := ubuntu_cve.Candidate
			bytes, err := json.Marshal(ubuntu_cve)
			uutil.ErrFatal(err)

			// save
			err = b.Put([]byte(key), bytes)
			uutil.ErrFatal(err)
		}

		return nil
	})

	// save CVE ids for every package
	err = db.Update(func(tx *bbolt.Tx) error {
		b, err := tx.CreateBucketIfNotExists([]byte(CVE_PACKAGE_TABLE))
		uutil.ErrFatal(err)

		for key, value := range uop.CVEsForPackage {

			// value
			bytes, err := json.Marshal(value)
			uutil.ErrFatal(err)

			// save
			err = b.Put([]byte(key), bytes)
			uutil.ErrFatal(err)
		}

		return nil
	})

	fmt.Println("[-] Ubuntu NewDB End.")
}

func (ucp CVEParser) GetOneItemOnMetaData(lines []string, id *int) (string, string, error) {
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

func (ucp CVEParser) Parse(s string, uop *DBOperation) error {

	ubuntu_cve := UbuntuCVE{Patches: map[string]PatchData{}}
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

		patch_data := PatchData{DiffURLs: []string{}, SpecificPatchDatas: map[UbuntuVersion]SpecificPatchData{}}

		lines := strings.Split(block, "\n")
		if strings.Index(lines[0], ":") == -1 {
			continue
		}

		// get package name
		package_name_part := lines[0][:strings.Index(lines[0], ":")]
		package_name := package_name_part[strings.Index(package_name_part, "_")+1:]

		// get affected packages for every ubuntu version
		for lid := 1; lid < len(lines); lid++ {

			// ignore "Tags_...", "Priority_...", "Patches_..." in the current design
			if strings.Compare(lines[lid], "") == 0 || strings.HasPrefix(lines[lid], "Priority_") || strings.HasPrefix(lines[lid], "Tags_") ||
				strings.HasPrefix(lines[lid], "Patches_") {
				continue
			}

			// get patch URLs
			tokens := strings.Fields(lines[lid])
			if strings.Compare(tokens[0], "upstream:") == 0 || strings.Compare(tokens[0], "vendor:") == 0 ||
				strings.Compare(tokens[0], "suse:") == 0 || strings.Compare(tokens[0], "opensuse:") == 0 ||
				strings.Compare(tokens[0], "debdiff:") == 0 || strings.Compare(tokens[0], "other:") == 0 ||
				strings.Compare(tokens[0], "distro:") == 0 || strings.Compare(tokens[0], "debian:") == 0 ||
				strings.Compare(tokens[0], "android:") == 0 || strings.Compare(tokens[0], "ubuntu:") == 0 ||
				strings.Compare(tokens[0], "redhat:") == 0 || strings.Compare(tokens[0], "usptream:") == 0 {
				upstream_url := tokens[1]
				patch_data.DiffURLs = append(patch_data.DiffURLs, upstream_url)
				continue
			}

			// ignore "break-fix" in the current design
			if strings.HasSuffix(tokens[0], "break-fix:") {
				continue
			}

			// ex. package_and_patch: ["lucid_gcc-4.1:", "ignored", "(reached", "end-of-life)"]
			package_and_patch := strings.Fields(lines[lid])
			package_words := strings.Split(package_and_patch[0], "/")

			// get ubuntu version
			var ubuntu_version UbuntuVersion
			if words_len := len(package_words); words_len == 1 {

				// ex.) trusty_gcc-11: DNE
				if strings.Index(package_words[0], "_") == -1 {
					log.Logger.Infoln(package_words)
					return xerrors.Errorf("Bug: unknown package words pattern: %v\n", package_words)
				}
				env := package_words[0][:strings.Index(package_words[0], "_")]
				if !package_env[env] && !package_manager[env] {
					log.Logger.Infoln(package_words)
					return xerrors.Errorf("Bug: unknown environment: %v\n", env)
				}
				ubuntu_version = NewUbuntuVersion(env, "")

			} else if words_len == 2 {

				// ex.) trusty/esm_gcc-11: DNE,
				// special support
				package_words2 := strings.Split(package_words[1], "_")

				if all_support_versions[package_words[0]] {
					ubuntu_version = NewUbuntuVersion(package_words2[0], package_words[0])
				} else if package_env[package_words[0]] || package_manager[package_words[0]] {
					if !all_support_versions[package_words2[0]] {
						return xerrors.Errorf("Bug: cannot Parse specific ubuntu support.\n")
					}
					ubuntu_version = NewUbuntuVersion(package_words[0], package_words2[0])
				} else {
					return xerrors.Errorf("Bug: cannot parse special support. target: %v\n", package_words[0])
				}
			} else if words_len > 2 {
				return xerrors.Errorf("Bug: words_len > 2 error. words: %v\n", package_words)
			}

			// get patch data
			patch_words := package_and_patch[1:]
			var specific_patch_data SpecificPatchData
			switch {
			case len(patch_words) == 0:
				specific_patch_data = SpecificPatchData{Affected: "", SubInfo: ""}
			case len(patch_words) == 1:
				specific_patch_data = SpecificPatchData{Affected: patch_words[0], SubInfo: ""}
			case len(patch_words) > 1:
				sub_info := strings.Join(patch_words[1:], " ")
				specific_patch_data = SpecificPatchData{Affected: patch_words[0], SubInfo: sub_info}
			}
			patch_data.SpecificPatchDatas[ubuntu_version] = specific_patch_data
		}

		// update CVEsForPackage
		if cve_refs, ok := uop.CVEsForPackage[package_name]; ok {
			cve_refs = append(cve_refs, ubuntu_cve.Candidate)
			uop.CVEsForPackage[package_name] = cve_refs
		} else {
			uop.CVEsForPackage[package_name] = []string{ubuntu_cve.Candidate}
		}

		// append patch data of the package for CVE
		ubuntu_cve.Patches[package_name] = patch_data
	}
	// update UbuntuCVEs
	uop.UbuntuCVEs = append(uop.UbuntuCVEs, ubuntu_cve)

	return nil
}
