package dto

type GetWhoisDataRequest struct {
	Domain string `json:"domain" validate:"required,max=255"`
}

type BulkGetWhoisDataRequest struct {
	Domains []string `json:"domains" validate:"required,min=1,max=200"`
}
