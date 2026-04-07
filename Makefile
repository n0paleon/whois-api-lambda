.PHONY: help build clean test deploy destroy plan init lint fmt vet

help:
	@echo "WHOIS API Lambda Makefile"
	@echo ""
	@echo "Available targets:"
	@awk 'BEGIN {FS = ":.*?## "} /^[a-zA-Z_-]+:.*?## / {printf "  \033[36m%-15s\033[0m %s\n", $$1, $$2}' $(MAKEFILE_LIST)

# Build targets
build:
	@echo "Building Lambda binary..."
	GOOS=linux GOARCH=arm64 CGO_ENABLED=0 go build -ldflags="-s -w" -trimpath -o bootstrap cmd/lambda/main.go
	@echo "Creating deployment package..."
	mkdir -p build

# 	Compress the binary with UPX
	upx -3 bootstrap

	zip -q build/lambda.zip bootstrap
	rm bootstrap
	@echo "Build complete: build/lambda.zip"

clean:
	@echo "Cleaning build artifacts..."
	rm -rf build
	@echo "Clean complete"

test:
	@echo "Running tests..."
	go test ./...

lint: ## Run golangci-lint
	@echo "Running linter..."
	golangci-lint run

fmt:
	@echo "Formatting code..."
	go fmt ./...

vet:
	@echo "Running go vet..."
	go vet ./...

init:
	@echo "Initializing Terraform..."
	terraform -chdir=terraform init

plan: build
	@echo "Planning Terraform changes..."
	terraform -chdir=terraform plan -var-file="terraform.tfvars"

apply: build
	@echo "Applying Terraform changes..."
	terraform -chdir=terraform apply -var-file="terraform.tfvars"

destroy:
	@echo "Destroying Terraform resources..."
	terraform -chdir=terraform destroy -var-file="terraform.tfvars"

deploy: init apply
	@echo "Deployment complete!"
	@echo "API URL: $$(terraform -chdir=terraform output api_invoke_url)"

test-api:
	@echo "Testing API endpoint..."
	@API_URL=$$(terraform -chdir=terraform output -raw api_invoke_url 2>/dev/null); \
	if [ -z "$$API_URL" ]; then \
		echo "API URL not found. Make sure Terraform has been applied."; \
		exit 1; \
	fi; \
	echo "API URL: $$API_URL"; \
	curl -X GET "$$API_URL/whois-api/whois/example.com" || echo "API test failed"

config:
	@echo "Setting up Terraform configuration..."
	cp terraform/terraform.tfvars.example terraform/terraform.tfvars
	@echo "Edit terraform/terraform.tfvars to customize your deployment"

setup: config init 
	@echo "Setup complete. Run 'make build && make plan' to continue"

dev: fmt vet lint test build
	@echo "Development pipeline complete"

ci: fmt vet lint test build plan
	@echo "CI pipeline complete"