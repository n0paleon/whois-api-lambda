package main

import (
	"whois-api-lambda/core"
	"whois-api-lambda/handler"

	"github.com/aws/aws-lambda-go/lambda"
)

func main() {
	svc := core.NewWhoisService()
	handler := handler.InitializeLambdaHandler(svc)

	lambda.Start(handler.HandleRequest)
}
