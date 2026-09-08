#!/usr/bin/env bash
# SPDX-License-Identifier: LGPL-2.1-or-later
# Build the prospero-win PE mapping gate as a native PS5 title.
#
# Phase 0 gate 1 needs no shaders and no GPU: it maps Windows images and
# reports the graph through ps5log/1. The staged Windows binaries are read
# from a private path the operator passes in and are never committed.
#
# Environment:
#   PS5_NATIVE_FOUNDATION  boilerplate checkout (default .deps/, pinned)
#   PS5LOG_DEV_CONF        private dev.conf copied into the title
#   PW_STAGE_INPUT         private directory holding the PE images to stage
#   PW_ROOT_MODULE         root image inside that directory (default sample.exe)
#   PW_SAMPLE              1 stages generated synthetic images instead of a
#                          private directory (default 0)
#   PW_COMPAT32_TRANSFER   1 attempts the gate 0.2a far transfer into 32-bit
#                          compatibility mode (default 0: install and report
#                          the descriptors only, which cannot fault)
#   PW_FOUNDATION_READY    1 trusts an already prepared foundation checkout
#                          and verifies its artifacts instead of rebuilding
#                          its dependencies, which would mutate a tree the
#                          laboratory's other projects share (default 0)
set -euo pipefail

root=$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")/.." && pwd)
pin=37dd53602bdead63936f718004555ba10154be48
url=https://github.com/mpereiraesaa/ps5-native-app-boilerplate.git
foundation=${PS5_NATIVE_FOUNDATION:-$root/.deps/ps5-native-app-boilerplate}
dev_conf=${PS5LOG_DEV_CONF:-$root/dev.conf}
stage_input=${PW_STAGE_INPUT:-}
root_module=${PW_ROOT_MODULE:-sample.exe}
use_sample=${PW_SAMPLE:-0}
compat32_transfer=${PW_COMPAT32_TRANSFER:-0}

[[ $use_sample == 0 || $use_sample == 1 ]] || {
    echo "PW_SAMPLE must be 0 or 1" >&2; exit 2; }
[[ $compat32_transfer == 0 || $compat32_transfer == 1 ]] || {
    echo "PW_COMPAT32_TRANSFER must be 0 or 1" >&2; exit 2; }
[[ $root_module =~ ^[A-Za-z0-9_.-]+$ ]] || {
    echo "PW_ROOT_MODULE must be a bare file name" >&2; exit 2; }
if [[ $use_sample == 0 && -z $stage_input ]]; then
    echo "PW_STAGE_INPUT or PW_SAMPLE=1 is required" >&2; exit 2
fi
if [[ $use_sample == 0 && ! -d $stage_input ]]; then
    echo "PW_STAGE_INPUT must name a directory" >&2; exit 2
fi

if [[ ! -d $foundation/.git ]]; then
    mkdir -p -- "$(dirname -- "$foundation")"
    git clone --filter=blob:none "$url" "$foundation"
fi
actual=$(git -C "$foundation" rev-parse HEAD)
if [[ $actual != "$pin" ]]; then
    git -C "$foundation" fetch origin "$pin"
    git -C "$foundation" checkout --detach "$pin"
fi
[[ $(git -C "$foundation" rev-parse HEAD) == "$pin" ]] || {
    echo "native foundation pin verification failed" >&2; exit 2; }

sdk="$foundation/.deps/native/ps5-payload-sdk"
native="$foundation/tooling/native"
tool="$foundation/build/host/ps5-native-tool"

# The pinned foundation is often a checkout shared with the laboratory's
# other projects. Rebuilding its dependencies mutates that tree and reaches
# the network, so when it is already complete, verify it instead.
if [[ ${PW_FOUNDATION_READY:-0} == 1 ]]; then
    for artifact in "$sdk/bin/prospero-lld" "$sdk/target/lib/libkernel.so" \
                    "$foundation/runtime/libc.prx" \
                    "$native/ps5-pie.ld" "$native/app_crt.cpp"; do
        [[ -e $artifact ]] || {
            echo "PW_FOUNDATION_READY=1 but $artifact is missing" >&2
            exit 2
        }
    done
    echo "using the prepared foundation at $foundation (deps not rebuilt)"
else
    make -C "$foundation" deps libc >/dev/null
fi
if [[ ! -x $tool ]]; then
    zlib_root="$foundation/.deps/native/zlib/root"
    zlib_archive=$(find "$zlib_root" -type f -name libz.a -print -quit)
    cxx=$(command -v clang++-18 || command -v clang++ || true)
    [[ -n $cxx && -n $zlib_archive ]] || {
        echo "native foundation host-tool dependencies are unavailable" >&2
        exit 2
    }
    mkdir -p "$foundation/build/host"
    "$cxx" -std=c++20 -O2 -Wall -Wextra -Werror \
        -I "$zlib_root/usr/include" \
        "$native/native_app_builder.cpp" "$native/self_container.cpp" \
        "$native/elf_object.cpp" "$native/sce_module_writer.cpp" \
        "$zlib_archive" -o "$tool"
fi
[[ -x $tool && -d $sdk && -f $foundation/runtime/libc.prx ]] || {
    echo "native foundation did not produce its SDK, tool and runtime" >&2
    exit 2
}

title_id=PPSA99995
build="$root/build/native"
dist="$root/dist/$title_id"
rm -rf -- "$build" "$dist"
mkdir -p "$build/obj" "$dist/sce_sys" "$dist/sce_module" "$dist/win"

cc=(env PS5_PAYLOAD_SDK="$sdk" sh "$foundation/tooling/prospero-clang18")
common=(-O2 -Wall -Wextra -Werror -ffunction-sections -fdata-sections
        -I"$root/include" -I"$root/src" -I"$root/native"
        -I"$root/native/ps5log"
        -DPW_STAGE_DIR='"/app0/win"'
        -DPW_ROOT_MODULE="\"$root_module\""
        -DPW_COMPAT32_TRANSFER="$compat32_transfer")

sources=(
    native/main.c native/pw_file_ps5.c native/pw_compat32_ps5.c
    native/pw_lowmem_ps5.c
    src/pe_image.c src/pe_import.c src/pe_layout.c src/pe_reloc.c
    src/pw_compat32.c src/pw_gate.c src/pw_loader.c src/pw_map.c
    src/pw_module_name.c src/pw_result.c src/pw_segment.c src/pw_vm.c
    src/pw_vm_posix.c src/pw_exec_probe.c src/pw_x86_block.c src/pw_guest_call.c src/pw_import_bind.c src/pw_win32.c src/pw_guest_fp.c src/pw_guest_args.c src/pe_resource.c
)
objects=()
for source in "${sources[@]}"; do
    object="$build/obj/${source//\//_}.o"
    "${cc[@]}" -std=c11 "${common[@]}" -c "$root/$source" -o "$object"
    objects+=("$object")
done
"${cc[@]}" -c "$root/src/pw_win64_call.S" -o "$build/obj/pw_win64_call.o"
objects+=("$build/obj/pw_win64_call.o")
"${cc[@]}" -std=c11 "${common[@]}" \
    -include "$root/native/ps5log/ps5log_ps5_net.h" \
    -c "$root/native/ps5log/ps5log.c" -o "$build/obj/ps5log.o"
"${cc[@]}" -std=c11 "${common[@]}" \
    -c "$root/native/ps5log/ps5log_ps5_net.c" \
    -o "$build/obj/ps5log_ps5_net.o"
"${cc[@]}" -std=c++20 -O2 -Wall -Wextra -Werror -fno-exceptions -fno-rtti \
    -ffunction-sections -fdata-sections -c "$native/app_crt.cpp" \
    -o "$build/obj/app_crt.o"
objects+=("$build/obj/ps5log.o" "$build/obj/ps5log_ps5_net.o")

"$sdk/bin/prospero-lld" -T "$native/ps5-pie.ld" --eh-frame-hdr -e _start \
    -o "$build/llvm-pie.elf" "$build/obj/app_crt.o" "${objects[@]}" \
    --as-needed "$sdk"/target/lib/*.so
"$tool" link --in "$build/llvm-pie.elf" --out "$build/eboot.elf" \
    --stub-dir "$sdk/target/lib" --module-sdk 0x02000009 \
    --companion-sdk 0x08050001 --file-name eboot.elf
"$tool" self --sign --in "$build/eboot.elf" --out "$dist/eboot.bin" \
    --magic 0x1D3D154F
# The console installer copies icon0.png into /user/app/<title> and aborts
# the whole registration if it is absent, so it is not optional.
[[ -f $root/sce_sys/icon0.png ]] || python3 "$root/tools/make_icon.py"
cp "$root/sce_sys/param.json" "$root/sce_sys/icon0.png" "$dist/sce_sys/"
cp "$foundation/runtime/libc.prx" "$dist/sce_module/libc.prx"
if [[ -f $dev_conf ]]; then
    cp "$dev_conf" "$dist/dev.conf"
fi

# Stage the Windows images the gate will map. Names are lowercased because
# the console image cannot be listed: the provider resolves exact paths only.
if [[ $use_sample == 1 ]]; then
    python3 "$root/tools/make_test_pe.py" --out-dir "$dist/win"
else
    shopt -s nullglob
    for source in "$stage_input"/*; do
        [[ -f $source ]] || continue
        name=$(basename -- "$source")
        cp -- "$source" "$dist/win/${name,,}"
    done
    shopt -u nullglob
fi
[[ -f $dist/win/$root_module ]] || {
    echo "root module $root_module is not staged in $dist/win" >&2; exit 2; }

# Every dynamic import in the linked ELF is reviewed, per the porting
# playbook: an exported platform symbol is not a working one.
readelf=${LLVM_READELF:-$(command -v llvm-readelf-18 || command -v llvm-readelf || true)}
if [[ -n $readelf && -x $readelf ]]; then
    "$readelf" --dyn-syms "$build/llvm-pie.elf" \
        | awk '$7 == "UND" { print $8 }' | sort -u \
        > "$build/PW_DYNAMIC_IMPORTS.txt"
    if grep -qx 'strcasestr' "$build/PW_DYNAMIC_IMPORTS.txt"; then
        echo "strcasestr is banned: its provider is unusable on FW 12.02" >&2
        exit 2
    fi
    echo "dynamic imports recorded in $build/PW_DYNAMIC_IMPORTS.txt"
else
    echo "llvm-readelf unavailable: dynamic-import review skipped" >&2
fi

sha256sum "$build/eboot.elf" "$dist/eboot.bin"
echo "staged $(find "$dist/win" -type f | wc -l) image(s) under $dist/win"
