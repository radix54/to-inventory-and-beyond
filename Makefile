BIN := vaultshare

.PHONY: all build run test clean clean-data

all: build

# Create the Go module (and fetch golang.org/x/crypto) the first time.
go.mod:
	go mod init $(BIN)
	go mod tidy

build: go.mod
	go build -o $(BIN) .

run: build
	./$(BIN)

test: go.mod
	go test ./...

# Remove the compiled program.
clean:
	rm -f $(BIN)

# Remove everything the program writes: identities, vault entries, packages, extracted files.
clean-data:
	rm -f *.identity.json *.pub.json *.vault.json *.share.json extracted-* received-*

CDXGEN_EXE := cdxgen
CDXGEN_RESULT := cdxgen.json
HOST_ARCHITECTURE := $(shell uname -m)
ARCHITECTURE := $(if $(filter x86_64 amd64,$(HOST_ARCHITECTURE)),amd64,$(if $(filter aarch64 arm64,$(HOST_ARCHITECTURE)),arm64,$(HOST_ARCHITECTURE)))

download-cdxgen:
	curl --fail --location --retry 3 -o $(CDXGEN_EXE) https://github.com/cdxgen/cdxgen/releases/download/v13.7.0/cdxgen-linux-$(ARCHITECTURE)
	chmod +x $(CDXGEN_EXE)

cdxgen:
	./$(CDXGEN_EXE) --deep --type go --evidence --include-crypto -o $(CDXGEN_RESULT) .

docker-cdxgen:
# Run docker and copy the cdxgen.json file to the host machine.
	docker build -t cdxgen/cdxgen:latest -f Dockerfile .
	docker run --rm -v $(PWD):/app -w /app cdxgen/cdxgen:latest --deep --type go --evidence --include-crypto -o $(CDXGEN_RESULT) .

cbomkit:
	docker compose --profile ext-compliance up -d
