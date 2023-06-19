package types

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

type PackageDetail struct {
	Binaryp string `json:"binaryp"`
	Sourcep string `json:"sourcep"`
	Version string `json:"version"`
}
