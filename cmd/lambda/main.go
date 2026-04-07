package main

import (
	"fmt"
	"net/http"
	"os"
	"time"
	"whois-api-lambda/internal/adapters/handler"
	"whois-api-lambda/internal/adapters/whois"
	service "whois-api-lambda/internal/services"
	"whois-api-lambda/pkg/serializer"

	"whois-api-lambda/internal/adapters/llm"
	_ "whois-api-lambda/internal/adapters/workerpool"

	"github.com/akrylysov/algnhsa"
	"github.com/go-playground/validator/v10"
	"github.com/labstack/echo/v5"
	"github.com/labstack/echo/v5/middleware"
	log "github.com/sirupsen/logrus"
)

func init() {
	log.SetLevel(log.DebugLevel)
	log.SetOutput(os.Stdout)
}

type CustomValidator struct {
	validator *validator.Validate
}

func (cv *CustomValidator) Validate(i any) error {
	if err := cv.validator.Struct(i); err != nil {
		return echo.ErrBadRequest.Wrap(err)
	}
	return nil
}

func main() {
	// adapters
	whoisClient := whois.NewClient()
	llmParser := llm.NewOpenRouterLLMParser(os.Getenv("OPENROUTER_API_KEY"))

	whoisParserService := service.NewWhoisParserService(llmParser)
	whoisService := service.NewWhoisService(whoisClient, whoisParserService)
	apiGwHandler := handler.NewApiGateway(whoisService)

	e := echo.New()
	e.JSONSerializer = &serializer.CustomJSONSerializer{}
	e.Use(middleware.Recover())
	e.Validator = &CustomValidator{validator: validator.New()}

	r := e.Group("/whois-api")
	r.GET("/ping", func(c *echo.Context) error {
		return c.String(http.StatusOK, fmt.Sprintf("OK %s", time.Now().Format("2006-01-02 15:04:05 MST")))
	})
	r.GET("/available-tlds", apiGwHandler.GetAvailableTLDs)
	r.POST("/whois/raw", apiGwHandler.GetRawWhoisData)
	r.POST("/whois", apiGwHandler.GetWhoisData)
	r.POST("/whois/bulk", apiGwHandler.BulkGetWhoisData)

	algnhsa.ListenAndServe(e, nil)
}
