package handler

import (
	"context"
	"net/http"
	"whois-api-lambda/internal/apperrors"
	service "whois-api-lambda/internal/services"
	"whois-api-lambda/pkg/dto"

	"github.com/labstack/echo/v5"
	log "github.com/sirupsen/logrus"
)

type ApiGateway struct {
	whoisService *service.WhoisService
}

func NewApiGateway(whoisService *service.WhoisService) *ApiGateway {
	return &ApiGateway{
		whoisService: whoisService,
	}
}

func (h *ApiGateway) GetRawWhoisData(c *echo.Context) error {
	request := new(dto.GetWhoisDataRequest)

	if err := c.Bind(request); err != nil {
		return c.JSON(http.StatusBadRequest, dto.APIResponse{
			IsError:   true,
			ErrorCode: apperrors.ErrValidationError.Code,
			Message:   apperrors.ErrValidationError.Message,
		})
	}
	// Pass the normalized domain to the WHOIS adapter

	if err := c.Validate(request); err != nil {
		appErr := apperrors.ErrValidationError.WithDetail("validation", err.Error())
		return c.JSON(http.StatusBadRequest, dto.APIResponse{
			IsError:   true,
			ErrorCode: appErr.Code,
			Message:   appErr.Message,
			Data:      appErr.Detail,
		})
	}

	whoisData, err := h.whoisService.GetRawWhoisData(context.Background(), request.Domain)
	if err != nil {
		log.Error(err)

		appErr, ok := apperrors.AsAppError(err)
		if ok {
			return c.JSON(appErr.GetStatusCode(), dto.APIResponse{
				IsError:   true,
				ErrorCode: appErr.Code,
				Message:   appErr.Message,
				Data:      appErr.Detail,
			})
		}
		return c.JSON(http.StatusInternalServerError, dto.APIResponse{
			IsError:   true,
			ErrorCode: apperrors.CodeInternal,
			Message:   "failed to retrieve WHOIS data",
		})
	}

	data := map[string]interface{}{
		"domain": request.Domain,
		"whois":  whoisData,
	}

	return c.JSON(http.StatusOK, dto.APIResponse{
		IsError: false,
		Data:    data,
	})
}

func (h *ApiGateway) GetWhoisData(c *echo.Context) error {
	request := new(dto.GetWhoisDataRequest)

	if err := c.Bind(request); err != nil {
		return c.JSON(http.StatusBadRequest, dto.APIResponse{
			IsError:   true,
			ErrorCode: apperrors.ErrValidationError.Code,
			Message:   apperrors.ErrValidationError.Message,
		})
	}

	if err := c.Validate(request); err != nil {
		appErr := apperrors.ErrValidationError.WithDetail("validation", err.Error())
		return c.JSON(http.StatusBadRequest, dto.APIResponse{
			IsError:   true,
			ErrorCode: appErr.Code,
			Message:   appErr.Message,
			Data:      appErr.Detail,
		})
	}

	whoisData, err := h.whoisService.GetWhoisData(context.Background(), request.Domain)
	if err != nil {
		log.Error(err)

		appErr, ok := apperrors.AsAppError(err)
		if ok {
			return c.JSON(appErr.GetStatusCode(), dto.APIResponse{
				IsError:   true,
				ErrorCode: appErr.Code,
				Message:   appErr.Message,
				Data:      appErr.Detail,
			})
		}
		return c.JSON(http.StatusInternalServerError, dto.APIResponse{
			IsError:   true,
			ErrorCode: apperrors.CodeInternal,
			Message:   "failed to retrieve WHOIS data",
		})
	}

	return c.JSON(http.StatusOK, dto.APIResponse{
		IsError: false,
		Data:    whoisData,
	})
}

func (h *ApiGateway) BulkGetWhoisData(c *echo.Context) error {
	request := new(dto.BulkGetWhoisDataRequest)

	if err := c.Bind(request); err != nil {
		return c.JSON(http.StatusBadRequest, dto.APIResponse{
			IsError:   true,
			ErrorCode: apperrors.ErrValidationError.Code,
			Message:   apperrors.ErrValidationError.Message,
		})
	}

	if err := c.Validate(request); err != nil {
		appErr := apperrors.ErrValidationError.WithDetail("validation", err.Error())
		return c.JSON(http.StatusBadRequest, dto.APIResponse{
			IsError:   true,
			ErrorCode: appErr.Code,
			Message:   appErr.Message,
			Data:      appErr.Detail,
		})
	}

	whoisDataList, err := h.whoisService.BulkGetWhoisData(context.Background(), request.Domains)
	if err != nil {
		log.Error(err)

		appErr, ok := apperrors.AsAppError(err)
		if ok {
			return c.JSON(appErr.GetStatusCode(), dto.APIResponse{
				IsError:   true,
				ErrorCode: appErr.Code,
				Message:   appErr.Message,
				Data:      appErr.Detail,
			})
		}
		return c.JSON(http.StatusInternalServerError, dto.APIResponse{
			IsError:   true,
			ErrorCode: apperrors.CodeInternal,
			Message:   "failed to retrieve WHOIS data",
		})
	}

	return c.JSON(http.StatusOK, dto.APIResponse{
		IsError: false,
		Data:    whoisDataList,
	})
}

func (h *ApiGateway) GetAvailableTLDs(c *echo.Context) error {
	return c.JSON(http.StatusOK, dto.APIResponse{
		IsError: false,
		Data: h.whoisService.GetAvailableTLDs(),
	})
}