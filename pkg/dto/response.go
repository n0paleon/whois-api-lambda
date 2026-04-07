package dto

type APIResponse struct {
	IsError   bool   `json:"is_error"`
	ErrorCode string `json:"error_code,omitempty"`
	Message   string `json:"message,omitempty"`
	Data      any    `json:"data"`
}
