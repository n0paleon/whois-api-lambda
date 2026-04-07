package services

import (
	"context"

	"whois-api-lambda/internal/apperrors"
	"whois-api-lambda/internal/domain"
	"whois-api-lambda/internal/ports"

	parser "github.com/likexian/whois-parser"
	"github.com/sirupsen/logrus"
)

type WhoisParserService struct {
	llmParser ports.LLMParser
}

func NewWhoisParserService(llmParser ports.LLMParser) *WhoisParserService {
	return &WhoisParserService{
		llmParser: llmParser,
	}
}

func (s *WhoisParserService) Parse(ctx context.Context, whoisData string, targetDomain string) (*domain.WhoisInfo, error) {
	result, err := s.ParseWithLLM(ctx, whoisData, targetDomain)
	if err != nil {
		if appErr, ok := apperrors.AsAppError(err); ok {
			return nil, appErr
		}

		logrus.Error("LLM Parser error", err.Error())

		logrus.Debug("WHOIS Parser: fallback to manual whois-parser")
		return s.ParseWithWhoisParser(ctx, whoisData, targetDomain)
	}
	logrus.Debug("WHOIS Parser: completed via LLM")
	return result, nil
}

func (s *WhoisParserService) ParseWithWhoisParser(ctx context.Context, whoisData string, targetDomain string) (*domain.WhoisInfo, error) {
	parsedResult, err := parser.Parse(whoisData)
	if err != nil {
		return nil, err
	}

	whoisInfo := new(domain.WhoisInfo)

	if parsedResult.Domain != nil {
		whoisInfo.Domain = &domain.WhoisDomain{
			ID:          parsedResult.Domain.ID,
			Domain:      parsedResult.Domain.Domain,
			Punycode:    parsedResult.Domain.Punycode,
			Name:        parsedResult.Domain.Name,
			Extension:   parsedResult.Domain.Extension,
			WhoisServer: parsedResult.Domain.WhoisServer,
			Status:      parsedResult.Domain.Status,
			NameServers: parsedResult.Domain.NameServers,
			DNSSec:      parsedResult.Domain.DNSSec,
			CreatedAt:   parsedResult.Domain.CreatedDateInTime,
			UpdatedAt:   parsedResult.Domain.UpdatedDateInTime,
			ExpiresAt:   parsedResult.Domain.ExpirationDateInTime,
		}
	}
	if parsedResult.Registrar != nil {
		whoisInfo.Registrar = &domain.WhoisContact{
			ID:           parsedResult.Registrar.ID,
			Name:         parsedResult.Registrar.Name,
			Organization: parsedResult.Registrar.Organization,
			Street:       parsedResult.Registrar.Street,
			City:         parsedResult.Registrar.City,
			Province:     parsedResult.Registrar.Province,
			PostalCode:   parsedResult.Registrar.PostalCode,
			Country:      parsedResult.Registrar.Country,
			Phone:        parsedResult.Registrar.Phone,
			PhoneExt:     parsedResult.Registrar.PhoneExt,
			Fax:          parsedResult.Registrar.Fax,
			FaxExt:       parsedResult.Registrar.FaxExt,
			Email:        parsedResult.Registrar.Email,
			ReferralURL:  parsedResult.Registrar.ReferralURL,
		}
	}
	if parsedResult.Registrant != nil {
		whoisInfo.Registrant = &domain.WhoisContact{
			ID:           parsedResult.Registrant.ID,
			Name:         parsedResult.Registrant.Name,
			Organization: parsedResult.Registrant.Organization,
			Street:       parsedResult.Registrant.Street,
			City:         parsedResult.Registrant.City,
			Province:     parsedResult.Registrant.Province,
			PostalCode:   parsedResult.Registrant.PostalCode,
			Country:      parsedResult.Registrant.Country,
			Phone:        parsedResult.Registrant.Phone,
			PhoneExt:     parsedResult.Registrant.PhoneExt,
			Fax:          parsedResult.Registrant.Fax,
			FaxExt:       parsedResult.Registrant.FaxExt,
			Email:        parsedResult.Registrant.Email,
			ReferralURL:  parsedResult.Registrant.ReferralURL,
		}
	}
	if parsedResult.Administrative != nil {
		whoisInfo.Administrative = &domain.WhoisContact{
			ID:           parsedResult.Administrative.ID,
			Name:         parsedResult.Administrative.Name,
			Organization: parsedResult.Administrative.Organization,
			Street:       parsedResult.Administrative.Street,
			City:         parsedResult.Administrative.City,
			Province:     parsedResult.Administrative.Province,
			PostalCode:   parsedResult.Administrative.PostalCode,
			Country:      parsedResult.Administrative.Country,
			Phone:        parsedResult.Administrative.Phone,
			PhoneExt:     parsedResult.Administrative.PhoneExt,
			Fax:          parsedResult.Administrative.Fax,
			FaxExt:       parsedResult.Administrative.FaxExt,
			Email:        parsedResult.Administrative.Email,
			ReferralURL:  parsedResult.Administrative.ReferralURL,
		}
	}
	if parsedResult.Technical != nil {
		whoisInfo.Technical = &domain.WhoisContact{
			ID:           parsedResult.Technical.ID,
			Name:         parsedResult.Technical.Name,
			Organization: parsedResult.Technical.Organization,
			Street:       parsedResult.Technical.Street,
			City:         parsedResult.Technical.City,
			Province:     parsedResult.Technical.Province,
			PostalCode:   parsedResult.Technical.PostalCode,
			Country:      parsedResult.Technical.Country,
			Phone:        parsedResult.Technical.Phone,
			PhoneExt:     parsedResult.Technical.PhoneExt,
			Fax:          parsedResult.Technical.Fax,
			FaxExt:       parsedResult.Technical.FaxExt,
			Email:        parsedResult.Technical.Email,
			ReferralURL:  parsedResult.Technical.ReferralURL,
		}
	}
	if parsedResult.Billing != nil {
		whoisInfo.Billing = &domain.WhoisContact{
			ID:           parsedResult.Billing.ID,
			Name:         parsedResult.Billing.Name,
			Organization: parsedResult.Billing.Organization,
			Street:       parsedResult.Billing.Street,
			City:         parsedResult.Billing.City,
			Province:     parsedResult.Billing.Province,
			PostalCode:   parsedResult.Billing.PostalCode,
			Country:      parsedResult.Billing.Country,
			Phone:        parsedResult.Billing.Phone,
			PhoneExt:     parsedResult.Billing.PhoneExt,
			Fax:          parsedResult.Billing.Fax,
			FaxExt:       parsedResult.Billing.FaxExt,
			Email:        parsedResult.Billing.Email,
			ReferralURL:  parsedResult.Billing.ReferralURL,
		}
	}

	return whoisInfo, nil
}

func (s *WhoisParserService) ParseWithLLM(ctx context.Context, whoisData string, targetDomain string) (*domain.WhoisInfo, error) {
	return s.llmParser.Parse(ctx, whoisData, targetDomain)
}
