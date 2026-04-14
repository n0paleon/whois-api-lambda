package llm

import "whois-api-lambda/internal/domain"

func isContactEmpty(contact *domain.WhoisContact) bool {
	if contact == nil {
		return true
	}
	return contact.ID == "" &&
		contact.Name == "" &&
		contact.Organization == "" &&
		contact.Street == "" &&
		contact.City == "" &&
		contact.Province == "" &&
		contact.PostalCode == "" &&
		contact.Country == "" &&
		contact.Phone == "" &&
		contact.PhoneExt == "" &&
		contact.Fax == "" &&
		contact.FaxExt == "" &&
		contact.Email == "" &&
		contact.ReferralURL == ""
}
