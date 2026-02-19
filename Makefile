.PHONY: build build-ui test clean

BINARY_NAME := aegis
BUILD_DIR   := build
ENTRY_MOD   := aegis.cli
ENTRY_FUNC  := main

build:
	@mkdir -p $(BUILD_DIR)/.work
	@echo 'from $(ENTRY_MOD) import $(ENTRY_FUNC); $(ENTRY_FUNC)()' > $(BUILD_DIR)/.work/entry.py
	pyinstaller --onefile \
		--name $(BINARY_NAME) \
		--distpath $(BUILD_DIR) \
		--workpath $(BUILD_DIR)/.work \
		--specpath $(BUILD_DIR)/.work \
		--clean --noconfirm \
		--paths src \
		$(BUILD_DIR)/.work/entry.py
	@echo "Built: $(BUILD_DIR)/$(BINARY_NAME)"

GO := $(HOME)/go-sdk/go/bin/go

build-ui:
	@mkdir -p $(BUILD_DIR)
	cd ui && CGO_ENABLED=1 $(GO) build -ldflags="-s -w" -o ../$(BUILD_DIR)/$(BINARY_NAME)-ui .
	@echo "Built: $(BUILD_DIR)/$(BINARY_NAME)-ui"

test:
	python3 -m pytest tests/ -q

clean:
	rm -rf $(BUILD_DIR) dist *.spec
