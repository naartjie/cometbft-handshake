# make help colorful: https://gist.github.com/prwhite/8168133?permalink_comment_id=2278355#gistcomment-2278355
# COLORS
GREEN  := $(shell tput -Txterm setaf 2)
YELLOW := $(shell tput -Txterm setaf 3)
WHITE  := $(shell tput -Txterm setaf 7)
RESET  := $(shell tput -Txterm sgr0)

TARGET_MAX_CHAR_NUM=20
## Show this help screen
help:
	@echo ''
	@echo 'Usage:'
	@echo '  ${YELLOW}make${RESET} ${GREEN}<target>${RESET}'
	@echo ''
	@echo 'Targets:'
	@awk '/^[a-zA-Z\-\_0-9]+:/ { \
		helpMessage = match(lastLine, /^## (.*)/); \
		if (helpMessage) { \
			helpCommand = substr($$1, 0, index($$1, ":")-1); \
			helpMessage = substr(lastLine, RSTART + 3, RLENGTH); \
			printf "  ${YELLOW}%-$(TARGET_MAX_CHAR_NUM)s${RESET} ${GREEN}%s${RESET}\n", helpCommand, helpMessage; \
		} \
	} \
	{ lastLine = $$0 }' $(MAKEFILE_LIST)

## initalize ~/.cometbft/{data,config}
init-target:
	@test -d ~/.cometbft || (cd target-node && go run cmd/cometbft/main.go init)

## start cometbf target node for testing
run-target: init-target
	cd target-node && go run cmd/cometbft/main.go node --proxy_app=kvstore --log_level=error

## start cometbf target node for testing (with logging enabled - more verbose)
run-target-debug: init-target
	cd target-node && go run cmd/cometbft/main.go node --proxy_app=kvstore --log_level=debug

## run the rust handshake code
run-handshake:
	cargo run --bin handshake