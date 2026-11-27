#!/usr/bin/env bash
# Run against an already-built Linux Xenolith CLI.
set -euo pipefail

if [[ $# -ne 2 ]]; then
    echo "usage: bash $0 <xenolith-cli> <fixture-and-report-dir>" >&2
    exit 2
fi

cli=$(realpath -- "$1")
test -x "$cli"
tests_dir=$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd)
samples_dir="$tests_dir/../samples/hello-elf"
mkdir -p -- "$2"
output=$(cd -- "$2" && pwd)
work=$(mktemp -d "$output/elf-smoke.XXXXXXXX")

finish() {
    local status=$?
    trap - EXIT
    printf '%s\n' "$status" > "$work/run.exit-code"
    date -u +%FT%TZ > "$work/finished-utc.txt"
    if ! (cd -- "$work" && find . -type f ! -name SHA256SUMS -print0 |
        LC_ALL=C sort -z | xargs -0 sha256sum > SHA256SUMS); then
        status=1
        printf '%s\n' "$status" > "$work/run.exit-code"
    fi
    printf 'ELF smoke exit=%s, evidence=%s\n' "$status" "$work"
    exit "$status"
}
trap finish EXIT

run_command() {
    local label=$1
    shift
    local status=0
    printf '%q ' "$@" > "$work/$label.command"
    printf '\n' >> "$work/$label.command"
    "$@" > "$work/$label.stdout" 2> "$work/$label.stderr" || status=$?
    printf '%s\n' "$status" > "$work/$label.exit-code"
    printf '%s\t%s\n' "$label" "$status" >> "$work/commands.tsv"
    printf '%s exit=%s\n' "$label" "$status"
    if [[ $status -ne 0 ]]; then
        cat -- "$work/$label.stdout"
        cat -- "$work/$label.stderr" >&2
    fi
    return "$status"
}

date -u +%FT%TZ > "$work/started-utc.txt"
mkdir -- "$work/inputs"
cp -- "${BASH_SOURCE[0]}" "$tests_dir/elf-library-host.c" \
    "$samples_dir/hello.c" "$samples_dir/eh.cpp" "$samples_dir/eh_driver.c" \
    "$samples_dir/feat.c" "$samples_dir/feat_driver.c" "$samples_dir/feat.map" \
    "$work/inputs/"
sha256sum -- "$cli" "$work/inputs/"* > "$work/input-sha256.txt"
run_command cli-version "$cli" --version
run_command gcc-version gcc --version
run_command gxx-version g++ --version
run_command environment uname -a

original_exe="$work/hello-elf"
packed_exe="$work/hello-elf.xl.elf"
original_so="$work/libhello-elf.so"
packed_so="$work/libhello-elf.xl.so"
host="$work/elf-library-host"
run_command build-pie gcc -fPIE -pie -o "$original_exe" "$work/inputs/hello.c"
run_command build-so gcc -fPIC -shared -o "$original_so" "$work/inputs/hello.c"
run_command build-host gcc -Wall -Wextra -Werror -o "$host" "$work/inputs/elf-library-host.c" -ldl
# Keep the ABI functions out of line and enable the existing tail-call sample.
run_command build-eh g++ -O2 -fno-inline -fPIC -shared -o "$work/libeh.so" "$work/inputs/eh.cpp"
run_command build-eh-driver gcc -O1 -Wall -Wextra -Werror -fno-omit-frame-pointer \
    -o "$work/eh-driver" "$work/inputs/eh_driver.c" -ldl
run_command build-feat gcc -O2 -fno-inline -fPIC -shared \
    -Wl,--version-script="$work/inputs/feat.map" -o "$work/libfeat.so" "$work/inputs/feat.c"
run_command build-feat-driver gcc -O1 -Wall -Wextra -Werror \
    -o "$work/feat-driver" "$work/inputs/feat_driver.c" -ldl

hello=xenolith-hello-elf
printf '%s\n' "$hello" > "$work/expected-exe.stdout"
printf '%s\n' "$hello" "$hello" > "$work/expected-so.stdout"
printf '%s\n' 'FEAT MATRIX OK (ifunc=15 ver1=107 ver2=207 tls=18 all=244)' > "$work/expected-feat.stdout"
run_command original-pie "$original_exe"
run_command original-pie-matches diff -u "$work/expected-exe.stdout" "$work/original-pie.stdout"
run_command original-so "$host" "$original_so"
run_command original-so-matches diff -u "$work/expected-so.stdout" "$work/original-so.stdout"
run_command original-eh "$work/eh-driver" "$work/libeh.so"
run_command original-feat "$work/feat-driver" "$work/libfeat.so"
run_command original-feat-matches diff -u "$work/expected-feat.stdout" "$work/original-feat.stdout"

originals=(hello-elf libhello-elf.so libeh.so libfeat.so)
packed=(hello-elf.xl.elf libhello-elf.xl.so libeh.xl.so libfeat.xl.so)
for index in "${!originals[@]}"; do
    name=${originals[$index]}
    run_command "$name.pack" "$cli" pack "$work/$name" -o "$work/${packed[$index]}" --profile standard --json
    run_command "$name.original.inspect" "$cli" inspect "$work/$name" --json
    run_command "$name.packed.inspect" "$cli" inspect "$work/${packed[$index]}" --json
    # The existing CI artifact glob collects these uniquely named reports.
    ln -- "$work/$name.packed.inspect.stdout" "$output/${work##*/}.$name.inspect.json"
done
run_command inspect-contract python3 - "$work" <<'PY'
import json
import pathlib
import sys

work = pathlib.Path(sys.argv[1])
for name in ('hello-elf', 'libhello-elf.so', 'libeh.so', 'libfeat.so'):
    for packed in (False, True):
        state = 'packed' if packed else 'original'
        path = work / f'{name}.{state}.inspect.stdout'
        info = json.loads(path.read_bytes())
        assert info['packed'] is packed, (path, info)
        assert info['pie'] is (name == 'hello-elf') and info['aslr'] is True, (path, info)
        assert info['format'] == 'elf64-dyn' and info['machine'] == 'x86_64', (path, info)
        assert info['backend'] == ('pic-stub+xl-core' if packed else 'none'), (path, info)
        assert info['report_version'] == 1 and info['probes'] == [], (path, info)
PY

no_header_so="$work/libhello-elf.no-eh-header.so"
no_header_packed="$work/libhello-elf.no-eh-header.xl.so"
run_command remove-input-eh-header python3 - "$original_so" "$no_header_so" <<'PY'
import pathlib
import struct
import sys

source = bytearray(pathlib.Path(sys.argv[1]).read_bytes())
target = pathlib.Path(sys.argv[2])
phoff = struct.unpack_from('<Q', source, 32)[0]
phentsize = struct.unpack_from('<H', source, 54)[0]
phnum = struct.unpack_from('<H', source, 56)[0]
headers = [source[phoff + i * phentsize:phoff + (i + 1) * phentsize] for i in range(phnum)]
kept = [header for header in headers if struct.unpack_from('<I', header, 0)[0] != 0x6474E550]
assert len(kept) == phnum - 1, 'fixture must contain exactly one PT_GNU_EH_FRAME'
for index, header in enumerate(kept):
    start = phoff + index * phentsize
    source[start:start + phentsize] = header
    if struct.unpack_from('<I', header, 0)[0] == 6:  # PT_PHDR
        struct.pack_into('<Q', source, start + 32, len(kept) * phentsize)
        struct.pack_into('<Q', source, start + 40, len(kept) * phentsize)
struct.pack_into('<H', source, 56, len(kept))
target.write_bytes(source)
PY
run_command no-header.pack "$cli" pack "$no_header_so" -o "$no_header_packed" --profile standard --json
run_command no-header.original.inspect "$cli" inspect "$no_header_so" --json
run_command no-header.packed.inspect "$cli" inspect "$no_header_packed" --json
run_command no-header.original.load "$host" "$no_header_so"
run_command no-header.packed.load "$host" "$no_header_packed"
run_command no-header.load-matches diff -u "$work/no-header.original.load.stdout" "$work/no-header.packed.load.stdout"
run_command no-header-header-contract python3 - "$no_header_so" "$no_header_packed" <<'PY'
import pathlib
import struct
import sys

for index, filename in enumerate(sys.argv[1:]):
    image = pathlib.Path(filename).read_bytes()
    phoff = struct.unpack_from('<Q', image, 32)[0]
    phentsize = struct.unpack_from('<H', image, 54)[0]
    phnum = struct.unpack_from('<H', image, 56)[0]
    count = sum(
        struct.unpack_from('<I', image, phoff + i * phentsize)[0] == 0x6474E550
        for i in range(phnum)
    )
    assert count == index, (filename, count)
PY

if run_command exports-negative "$cli" inspect "$original_so" --exports --json; then
    echo 'expected ELF --exports --json to fail' >&2
    exit 1
fi
test ! -s "$work/exports-negative.stdout"
grep -Fq -- '--exports is unsupported for ELF inspection' "$work/exports-negative.stderr"

for run in 1 2 3; do
    # Execute the CLI output as written, with its original file mode.
    run_command "packed-pie-$run" "$packed_exe"
    run_command "packed-pie-$run-matches" diff -u "$work/original-pie.stdout" "$work/packed-pie-$run.stdout"
done
run_command packed-so "$host" "$packed_so"
run_command packed-so-matches diff -u "$work/original-so.stdout" "$work/packed-so.stdout"
run_command packed-eh "$work/eh-driver" "$work/libeh.xl.so"
run_command packed-eh-matches diff -u "$work/original-eh.stdout" "$work/packed-eh.stdout"
run_command packed-feat "$work/feat-driver" "$work/libfeat.xl.so"
run_command packed-feat-matches diff -u "$work/original-feat.stdout" "$work/packed-feat.stdout"

run_command original-eh-layout readelf -W -l -S "$work/libeh.so"
run_command packed-eh-layout readelf -W -l -S "$work/libeh.xl.so"
run_command original-feat-layout readelf -W -l -r --dyn-syms -V "$work/libfeat.so"
run_command packed-feat-layout readelf -W -l -r --dyn-syms -V "$work/libfeat.xl.so"
run_command feature-contract python3 - "$work" <<'PY'
import pathlib
import re
import sys

work = pathlib.Path(sys.argv[1])
for state in ('original', 'packed'):
    eh = (work / f'{state}-eh-layout.stdout').read_text()
    assert '.eh_frame' in eh and 'GNU_EH_FRAME' in eh, state
    assert eh.count('GNU_EH_FRAME') == 1, state
    feat = (work / f'{state}-feat-layout.stdout').read_text()
    assert re.search(r'IFUNC[^\n]*\bifunc_add\b', feat), state
    assert 'feat_ver@XLFEAT_1.0' in feat and 'feat_ver@@XLFEAT_2.0' in feat, state
    assert re.search(r'^\s*TLS\s', feat, re.MULTILINE), state
    assert 'R_X86_64_TPOFF64' in feat, state
    assert 'R_X86_64_DTPMOD64' in feat and '__tls_get_addr' in feat, state
PY

# The packer's unit tests consume target/hello-elf after this CI entry point.
# A previous input is accepted only when its bytes match this run's fixture.
if [[ -e "$output/hello-elf" || -L "$output/hello-elf" ]]; then
    run_command existing-unit-fixture cmp -- "$original_exe" "$output/hello-elf"
else
    run_command publish-unit-fixture ln -- "$original_exe" "$output/hello-elf"
fi

cat -- "$work/original-eh.stdout" "$work/packed-eh.stdout" \
    "$work/original-feat.stdout" "$work/packed-feat.stdout"
echo 'PIE (3 packed runs), shared-library load/reload, EH/ABI and IFUNC/versions/TLS matched the originals'
