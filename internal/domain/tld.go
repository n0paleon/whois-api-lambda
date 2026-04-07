package domain

type TLD struct {
	RootTLD            string   `json:"root_tld"`
	SubTLD             []string `json:"sub_tld"`
	RegistryOperator   string   `json:"registry_operator"`
	InfoURL            string   `json:"info_url"`
	Tags               []string `json:"tags"`
	Languages          []string `json:"languages"`
	AllowsIDN          bool     `json:"allows_idn"`
	AllowsRegistration bool     `json:"allows_registration"`
}
