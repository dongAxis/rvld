BINARY_NAME = rvld
BINARY_VERSION = 1.0.0
COMMIT_ID = $(shell git rev-list -1 HEAD)

TESTS := $(wildcard tests/*.sh)

build:
	@go build -ldflags "-X main.version=${BINARY_VERSION}-${COMMIT_ID}" -o $(BINARY_NAME) $(BINARY_NAME).go
	@ln -sf rvld ld

clean:
	go clean
	rm -rf out
	rm -rf ld

test: build
	@CC="riscv64-linux-gnu-gcc" \
	$(MAKE) $(TESTS)
	@printf '\e[32mPassed all tests\e[0m\n';

$(TESTS):
	@echo "Testing" $@
	@./$@
	@printf '\e[32mOK\e[0m\n';

.PHONY: build clean test $(TESTS)