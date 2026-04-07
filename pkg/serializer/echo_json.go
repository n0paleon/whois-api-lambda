package serializer

import (
	"github.com/goccy/go-json"

	"github.com/labstack/echo/v5"
)

type CustomJSONSerializer struct{}

func (c *CustomJSONSerializer) Serialize(ctx *echo.Context, i interface{}, indent string) error {
	enc := json.NewEncoder(ctx.Response())
	if indent != "" {
		enc.SetIndent("", indent)
	}
	return enc.Encode(i)
}

func (c *CustomJSONSerializer) Deserialize(ctx *echo.Context, target any) error {
	if err := json.NewDecoder(ctx.Request().Body).Decode(target); err != nil {
		return err
	}
	return nil
}