.PHONY: build

build:
	sam build

debug:
	go build -C src/ -o bootstrap main.go && sam local start-api --skip-pull-image