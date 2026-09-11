CC ?= cc
CFLAGS ?= -O2 -std=c11 -Wall -Wextra -Werror
BUILD := build/host
HEADERS := $(wildcard include/*.h src/*.h native/*.h)

.PHONY: all test sanitize audit inspect inspect-only sample native native-release clean

all: test audit

$(BUILD):
	mkdir -p $@

define test_rule
$(BUILD)/$(1): $(2) $(HEADERS) | $(BUILD)
	$(CC) $(CFLAGS) $$(filter %.c %.S,$$^) $(3) -o $$@
endef

CORE := src/pe_image.c src/pe_layout.c src/pe_reloc.c src/pe_import.c \
	src/pw_map.c src/pw_module_name.c src/pw_vm.c src/pw_vm_posix.c \
	src/pw_loader.c src/pw_result.c src/pw_segment.c src/pw_compat32.c

$(eval $(call test_rule,test_pe_image,tests/test_pe_image.c src/pe_image.c src/pw_result.c,))
$(eval $(call test_rule,test_pe_resource,tests/test_pe_resource.c src/pe_resource.c src/pe_image.c,))
$(eval $(call test_rule,test_pw_guest_heap,tests/test_pw_guest_heap.c src/pw_guest_heap.c src/pw_vm.c src/pw_vm_posix.c,))
$(eval $(call test_rule,test_pw_registry,tests/test_pw_registry.c src/pw_registry.c,))
$(eval $(call test_rule,test_pw_registry_store,tests/test_pw_registry_store.c src/pw_registry_store.c src/pw_registry.c,))
$(eval $(call test_rule,test_pw_ini,tests/test_pw_ini.c src/pw_ini.c,))
$(eval $(call test_rule,test_pw_gdi,tests/test_pw_gdi.c src/pw_gdi.c,))
$(eval $(call test_rule,test_pw_gdi_abi,tests/test_pw_gdi_abi.c src/pw_win32.c src/pw_user32.c src/pw_gdi.c src/pw_crt_format.c src/pw_registry.c src/pw_guest_heap.c src/pw_guest_args.c src/pw_x87.c src/pw_guest_fp.c src/pw_guest_call.c src/pw_module_name.c src/pw_vm.c src/pw_vm_posix.c,))
$(eval $(call test_rule,test_pw_crt_format,tests/test_pw_crt_format.c src/pw_crt_format.c,))
$(eval $(call test_rule,test_pw_user32,tests/test_pw_user32.c src/pw_user32.c,))
$(eval $(call test_rule,test_pw_pad,tests/test_pw_pad.c src/pw_pad.c src/pw_user32.c,))
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
$(eval $(call test_rule,test_pw_x86_block,tests/test_pw_x86_block.c src/pw_x86_block.c src/pw_x87.c src/pw_guest_fp.c src/pw_guest_call.c src/pw_vm.c src/pw_vm_posix.c,))
$(eval $(call test_rule,test_pw_x86_cache,tests/test_pw_x86_cache.c src/pw_x86_cache.c,))
$(eval $(call test_rule,test_pw_x86_engine,tests/test_pw_x86_engine.c src/pw_x86_engine.c src/pw_x86_cache.c src/pw_x86_block.c src/pw_x87.c src/pw_guest_fp.c src/pw_vm.c src/pw_vm_posix.c,))
$(eval $(call test_rule,test_pw_guest_call,tests/test_pw_guest_call.c src/pw_guest_call.c src/pw_vm.c src/pw_vm_posix.c,))
$(eval $(call test_rule,test_pw_import_bind,tests/test_pw_import_bind.c src/pw_import_bind.c $(CORE),))
$(eval $(call test_rule,test_pw_win32,tests/test_pw_win32.c src/pw_win32.c src/pw_user32.c src/pw_gdi.c src/pw_crt_format.c src/pw_registry.c src/pw_guest_heap.c src/pw_guest_args.c src/pw_x87.c src/pw_guest_fp.c src/pw_guest_call.c src/pw_module_name.c src/pw_vm.c src/pw_vm_posix.c,))
$(eval $(call test_rule,test_pw_guest_args,tests/test_pw_guest_args.c src/pw_guest_args.c,))
$(eval $(call test_rule,test_pw_time,tests/test_pw_time.c src/pw_win32.c src/pw_user32.c src/pw_gdi.c src/pw_crt_format.c src/pw_registry.c src/pw_guest_heap.c src/pw_guest_args.c src/pw_x87.c src/pw_guest_fp.c src/pw_guest_call.c src/pw_module_name.c src/pw_vm.c src/pw_vm_posix.c,))
$(eval $(call test_rule,test_pw_guest_fp,tests/test_pw_guest_fp.c src/pw_guest_fp.c,))
$(eval $(call test_rule,test_pw_x87,tests/test_pw_x87.c src/pw_x87.c src/pw_guest_fp.c,))
$(eval $(call test_rule,test_pw_audio_ps5,tests/test_pw_audio_ps5.c native/pw_audio_ps5.c,-DPW_AUDIO_PS5_HOST_TEST))
$(eval $(call test_rule,test_pw_pad_ps5,tests/test_pw_pad_ps5.c native/pw_pad_ps5.c src/pw_pad.c src/pw_user32.c,-DPW_PAD_PS5_HOST_TEST))
$(eval $(call test_rule,test_pw_state_ps5,tests/test_pw_state_ps5.c native/pw_state_ps5.c src/pw_registry_store.c src/pw_registry.c,-DPW_STATE_PS5_HOST_TEST))
$(eval $(call test_rule,test_pw_initterm,tests/test_pw_initterm.c src/pw_win32.c src/pw_user32.c src/pw_gdi.c src/pw_crt_format.c src/pw_registry.c src/pw_guest_heap.c src/pw_guest_args.c src/pw_x86_block.c src/pw_x87.c src/pw_guest_fp.c src/pw_guest_call.c src/pw_module_name.c src/pw_vm.c src/pw_vm_posix.c,))
$(eval $(call test_rule,test_pw_window,tests/test_pw_window.c src/pw_win32.c src/pw_user32.c src/pw_gdi.c src/pw_crt_format.c src/pw_registry.c src/pw_guest_heap.c src/pw_guest_args.c src/pw_x86_block.c src/pw_x87.c src/pw_guest_fp.c src/pw_guest_call.c src/pw_module_name.c src/pw_vm.c src/pw_vm_posix.c,))
$(eval $(call test_rule,trace_x86_entry,tools/trace_x86_entry.c src/pe_resource.c src/pw_x86_engine.c src/pw_x86_cache.c src/pw_x86_block.c src/pw_x87.c src/pw_win32.c src/pw_user32.c src/pw_gdi.c src/pw_crt_format.c src/pw_registry.c src/pw_guest_heap.c src/pw_guest_args.c src/pw_guest_fp.c src/pw_guest_call.c src/pw_import_bind.c $(CORE),))
$(eval $(call test_rule,classify_x86,tools/classify_x86.c src/pw_x86_block.c src/pw_x87.c src/pw_guest_fp.c,))
$(eval $(call test_rule,test_pw_win64,tests/test_pw_win64.c src/pw_exec_probe.c src/pw_win64_call.S $(CORE),))
$(eval $(call test_rule,inspect_pe,tools/inspect_pe.c $(CORE) src/pw_file_posix.c,))

TESTS := test_pw_guest_heap test_pw_registry test_pw_registry_store test_pw_ini test_pw_gdi test_pw_gdi_abi test_pw_crt_format test_pw_user32 test_pw_pad test_pe_resource test_pw_time test_pw_guest_args test_pw_initterm test_pw_window test_pw_guest_fp test_pe_image test_pe_layout test_pe_reloc test_pe_import \
	test_pw_module_name test_pw_vm test_pw_map test_pw_loader \
	test_pw_segment test_pw_compat32 test_pw_gate test_pw_win64 test_pw_x86_block test_pw_x86_cache test_pw_x86_engine test_pw_guest_call test_pw_import_bind test_pw_win32 test_pw_x87 test_pw_audio_ps5 test_pw_pad_ps5 test_pw_state_ps5

# The Python suites drive the built binaries: the evidence validator is
# tested against a transcript the real gate produced, and the Python PE
# encoder is cross-checked against the C parser.
test: $(addprefix $(BUILD)/,$(TESTS)) $(BUILD)/inspect_pe $(BUILD)/trace_x86_entry $(BUILD)/classify_x86
	@set -e; for test in $(addprefix $(BUILD)/,$(TESTS)); do $$test; done
	python3 tests/test_title_identity.py
	python3 tests/test_icon.py
	python3 tests/test_native_contract.py
	python3 tests/test_make_test_pe.py
	python3 tests/test_validate_pe_map_evidence.py
	python3 tests/test_validate_runtime_evidence.py
	python3 tests/test_x86_differential.py
	python3 tests/test_trace_x86_entry.py
	python3 tests/test_inventory_imports.py
	python3 tests/test_audit_wine_imports.py
	python3 tests/test_win32_catalog.py
	python3 tests/test_classify_x86.py
	python3 tests/test_startup_x87_contract.py
	python3 tests/test_build_source_oracle.py
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
