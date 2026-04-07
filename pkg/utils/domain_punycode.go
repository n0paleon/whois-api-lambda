package utils

import "golang.org/x/net/idna"

func GetDomainFormats(input string) (native, punycode string) {
	native, _ = idna.ToUnicode(input)
	punycode, _ = idna.ToASCII(input)
	return
}
