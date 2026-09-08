CC ?= cc
CFLAGS ?= -O2 -std=c11 -Wall -Wextra -Werror
BUILD := build/host

.PHONY: all test sanitize audit inspect inspect-only sample native native-release clean

all: test audit

$(BUILD):
	mkdir -p $@

define test_rule
$(BUILD)/$(1): $(2) | $(BUILD)
	$(CC) $(CFLAGS) $$^ $(3) -o $$@
endef

CORE := src/pe_image.c src/pe_layout.c src/pe_reloc.c src/pe_import.c \
	src/pw_map.c src/pw_module_name.c src/pw_vm.c src/pw_vm_posix.c \
	src/pw_loader.c src/pw_result.c src/pw_segment.c src/pw_compat32.c

$(eval $(call test_rule,test_pe_image,tests/test_pe_image.c src/pe_image.c src/pw_result.c,))
$(eval $(call test_rule,test_pe_layout,tests/test_pe_layout.c src/pe_image.c src/pe_layout.c src/pw_result.c,))
$(eval $(call test_rule,test_pe_reloc,tests/test_pe_reloc.c src/pe_image.c src/pe_reloc.c src/pw_result.c,))
$(eval $(call test_rule,test_pe_import,tests/test_pe_import.c src/pe_image.c src/pe_import.c src/pw_result.c,))
$(eval $(call test_rule,test_pw_module_name,tests/test_pw_module_name.c src/pw_module_name.c src/pw_result.c,))
$(eval $(call test_rule,test_pw_vm,tests/test_pw_vm.c src/pw_vm.c src/pw_vm_posix.c src/pw_result.c,))
$(eval $(call test_rule,test_pw_map,tests/test_pw_map.c $(CORE),))
$(eval $(call test_rule,test_pw_loader,tests/test_pw_loader.c $(CORE),))
$(eval $(call test_rule,test_pw_segment,tests/test_pw_segment.c src/pw_segment.c src/pw_result.c,))
$(eval $(call test_rule,test_pw_compat32,tests/test_pw_compat32.c src/pw_compat32.c src/pw_segment.c src/pw_result.c,))
$(eval $(call test_rule,test_pw_gate,tests/test_pw_gate.c $(CORE) src/pw_gate.c,))
$(eval $(call test_rule,test_pw_x86_block,tests/test_pw_x86_block.c src/pw_x86_block.c src/pw_vm.c src/pw_vm_posix.c,))
$(eval $(call test_rule,trace_x86_entry,tools/trace_x86_entry.c src/pw_x86_block.c $(CORE),))
$(eval $(call test_rule,test_pw_win64,tests/test_pw_win64.c src/pw_exec_probe.c src/pw_win64_call.S $(CORE),))
$(eval $(call test_rule,inspect_pe,tools/inspect_pe.c $(CORE) src/pw_file_posix.c,))

TESTS := test_pe_image test_pe_layout test_pe_reloc test_pe_import \
	test_pw_module_name test_pw_vm test_pw_map test_pw_loader \
	test_pw_segment test_pw_compat32 test_pw_gate test_pw_win64 test_pw_x86_block

# The Python suites drive the built binaries: the evidence validator is
# tested against a transcript the real gate produced, and the Python PE
# encoder is cross-checked against the C parser.
test: $(addprefix $(BUILD)/,$(TESTS)) $(BUILD)/inspect_pe $(BUILD)/trace_x86_entry
	@set -e; for test in $(addprefix $(BUILD)/,$(TESTS)); do $$test; done
	python3 tests/test_title_identity.py
	python3 tests/test_icon.py
	python3 tests/test_native_contract.py
	python3 tests/test_make_test_pe.py
	python3 tests/test_validate_pe_map_evidence.py
	python3 tests/test_x86_differential.py
	python3 tests/test_trace_x86_entry.py
	python3 tests/test_inventory_imports.py
	python3 tests/test_audit_wine_imports.py
	rm -rf build tools/__pycache__ tests/__pycache__

audit:
	python3 tools/audit_publication.py

# Rebuild so previously cached non-instrumented binaries cannot pass this gate.
sanitize:
	ASAN_OPTIONS=detect_leaks=1 UBSAN_OPTIONS=halt_on_error=1 $(MAKE) -B test CC=clang CFLAGS='-O1 -g -std=c11 -Wall -Wextra -Werror -fno-omit-frame-pointer -fsanitize=address,undefined'

# Structural report for a private Windows binary. Nothing is copied here.
#   make inspect PE_INPUT=/private/path/game.exe PE_DIR=/private/path
inspect: $(BUILD)/inspect_pe
	@test -n "$(PE_INPUT)" || { echo 'PE_INPUT is required' >&2; exit 2; }
	$(BUILD)/inspect_pe "$(PE_INPUT)" $(if $(PE_DIR),--dir "$(PE_DIR)",)

# Inventory a target even before its DLLs or low-address backend are available.
inspect-only: $(BUILD)/inspect_pe
	@test -n "$(PE_INPUT)" || { echo 'PE_INPUT is required' >&2; exit 2; }
	$(BUILD)/inspect_pe "$(PE_INPUT)" --no-map

# Synthetic images for a gate run that needs no proprietary input at all.
sample:
	@test -n "$(OUT_DIR)" || { echo 'OUT_DIR is required' >&2; exit 2; }
	python3 tools/make_test_pe.py --out-dir "$(OUT_DIR)"

native: test audit
	PW_SAMPLE=1 tools/build_native.sh

native-release: test audit
	tools/build_native.sh

clean:
	rm -rf build dist release tools/__pycache__ tests/__pycache__
