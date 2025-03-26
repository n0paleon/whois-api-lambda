package handler

import (
	"context"
	"fmt"
	"whois-api-lambda/core"

	"net/http"

	"github.com/aws/aws-lambda-go/events"
	"github.com/bytedance/sonic"
)

const contentType = "application/json"

type LambdaHandler struct {
	svc core.Whois
}

func InitializeLambdaHandler(svc core.Whois) *LambdaHandler {
	return &LambdaHandler{svc}
}

func (h *LambdaHandler) HandleRequest(ctx context.Context, request events.APIGatewayV2HTTPRequest) (events.APIGatewayV2HTTPResponse, error) {
	path := request.RawPath

	switch path {
	case "/available-tlds":
		data := h.svc.GetAvailableTLDs()
		return h.SendResponse(&core.APIResponse{
			Data:    data,
			Error:   false,
			Message: "",
		}, 200), nil
	case "/whois/lookup":
		var payload SingleWhoisLookup
		if err := h.ParseJSONBody(request, &payload); err != nil {
			return h.SendResponse(&core.APIResponse{
				Error:   true,
				Message: "invalid payload",
			}, 400), nil
		}

		result, err := h.svc.GetWhoisData(ctx, payload.Domain)
		if err != nil {
			return h.SendResponse(&core.APIResponse{
				Error:   true,
				Message: err.Error(),
			}, 400), nil
		}

		return h.SendResponse(&core.APIResponse{
			Data:  result,
			Error: false,
		}, 200), nil
	case "/whois/lookup/raw":
		var payload SingleWhoisLookup
		if err := h.ParseJSONBody(request, &payload); err != nil {
			return h.SendResponse(&core.APIResponse{
				Error:   true,
				Message: "invalid payload",
			}, 400), nil
		}

		result, err := h.svc.GetRawWhoisData(ctx, payload.Domain)
		if err != nil {
			return h.SendResponse(&core.APIResponse{
				Error:   true,
				Message: err.Error(),
			}, 400), nil
		}

		return h.SendResponse(&core.APIResponse{
			Data:  string(result),
			Error: false,
		}, 200), nil
	case "/whois/mass-lookup":
		var payload MassWhoisLookup
		if err := h.ParseJSONBody(request, &payload); err != nil {
			return h.SendResponse(&core.APIResponse{
				Error:   true,
				Message: "invalid payload",
			}, 400), nil
		}
		if len(payload.Domain) > 150 {
			return h.SendResponse(&core.APIResponse{
				Error:   true,
				Message: "Too man domains, maximum allowed is 150 domain/request",
			}, 400), nil
		}

		results, err := h.svc.MassWhoisLookup(ctx, payload.Domain)
		if err != nil {
			return h.SendResponse(&core.APIResponse{
				Error:   true,
				Message: err.Error(),
			}, 500), nil
		}

		responses := make([]*MassDomainQueryResponse, 0, len(results))
		for _, result := range results {
			response := new(MassDomainQueryResponse)
			response.DomainName = result.DomainName
			if result.Error != nil {
				response.Error = true
				response.Message = "error"
			} else {
				response.WhoisData = result.Data
			}

			responses = append(responses, response)
		}

		return h.SendResponse(&core.APIResponse{
			Data:  responses,
			Error: false,
		}, 200), nil
	case "/health-check":
		return h.SendResponse(&core.APIResponse{
			Data:    "OK",
			Error:   false,
			Message: "API is healthy and ready to accept incoming requests",
		}, 200), nil
	default:
		return h.SendResponse(&core.APIResponse{
			Data:    "",
			Error:   false,
			Message: "this is response from default route!",
		}, 200), nil
	}
}

func (h *LambdaHandler) SendResponse(data *core.APIResponse, statusCode int) events.APIGatewayV2HTTPResponse {
	jsonResponse, err := sonic.Marshal(data)
	if err != nil {
		errorBody := `{"error": "Internal Server Error"}`
		return events.APIGatewayV2HTTPResponse{
			StatusCode: http.StatusInternalServerError,
			Headers: map[string]string{
				"Content-Type": contentType,
			},
			Body: errorBody,
		}
	}

	return events.APIGatewayV2HTTPResponse{
		StatusCode: statusCode,
		Headers: map[string]string{
			"Content-Type": contentType,
		},
		Body: string(jsonResponse),
	}
}

func (h *LambdaHandler) ParseJSONBody(request events.APIGatewayV2HTTPRequest, v interface{}) error {
	if err := sonic.Unmarshal([]byte(request.Body), v); err != nil {
		return fmt.Errorf("failed to parse JSON: %w", err)
	}
	return nil
}
