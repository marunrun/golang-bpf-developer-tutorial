CLANG ?= clang
CFLAGS := -O2 -g -Wall

# Find all subdirectories under cmd/ using wildcard
CMD_DIRS := $(wildcard cmd/*)
SUBDIRS := $(notdir $(CMD_DIRS))

# Default target
all: build

# Set environment variables for all targets
export BPF_CLANG := $(CLANG)
export BPF_CFLAGS := $(CFLAGS)

# Define targets for each subdirectory
define make-project-targets
$(1):
	@echo "Building $(1)..."
	@cd cmd/$(1) && go generate ./... && go build -o ../../bin/$(1) .

generate-$(1):
	@echo "Generating $(1)..."
	@cd cmd/$(1) && go generate ./...

clean-$(1):
	@echo "Cleaning $(1)..."
	cd cmd/$(1) && rm -f *_bpfeb*.* *_bpfel*.*
	@cd bin && rm - $(1)
endef

# Apply the template to each subdirectory
$(foreach dir,$(SUBDIRS),$(eval $(call make-project-targets,$(dir))))

# Rules for all projects
build: $(SUBDIRS)

generate: $(addprefix generate-,$(SUBDIRS))

.PHONY: clean
clean: $(addprefix clean-,$(SUBDIRS))

# Debug target to print subdirectories
.PHONY: debug
debug:
	@echo "Subdirectories found:"
	@echo "$(SUBDIRS)"

# Help target
.PHONY: help
help:
	@echo "Available targets:"
	@echo "  all                  - Build all projects (default)"
	@echo "  build                - Build all projects"
	@echo "  generate             - Generate eBPF code for all projects"
	@echo "  clean                - Clean generated files from all projects"
	@echo "  <project-name>       - Build a specific project (e.g., 1-helloworld)"
	@echo "  generate-<project>   - Generate eBPF code for a specific project"
	@echo "  clean-<project>      - Clean generated files for a specific project"
	@echo "  debug                - Print subdirectories found"
	@echo "  help                 - Show this help message"

# Make all targets phony
.PHONY: all build generate clean $(SUBDIRS) $(addprefix generate-,$(SUBDIRS)) $(addprefix clean-,$(SUBDIRS))
