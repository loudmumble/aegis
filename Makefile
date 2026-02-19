.PHONY: install build test clean

BINARY_NAME := aegis
BUILD_DIR   := build
ENTRY_MOD   := aegis.cli
ENTRY_FUNC  := main

install:
	pip install -e .

build: install
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

test:
	python3 -m pytest tests/ -q

clean:
	rm -rf $(BUILD_DIR) dist *.spec
