if [[ "${BASH_SOURCE[0]}" == "$0" ]]; then
  echo "ERROR: bootstrap-rust-common.bash must be sourced by a versioned bootstrap." >&2
  exit 64
fi

if (( $# != 0 )); then
  echo "ERROR: ${bootstrap_release} bootstrap accepts no arguments." >&2
  exit 64
fi
if (( EUID != 0 )); then
  echo "ERROR: ${bootstrap_release} bootstrap must run as root." >&2
  exit 77
fi

readonly import_root=/var/lib/rdashboard-build/imports
readonly bootstrap_lock=/var/lib/rdashboard-build/bootstrap-rust.lock
readonly titanium=/usr/libexec/rdashboard/rdashboard-titanium
readonly -a wrappers=(ar c++ cc node ranlib)
readonly target=linux-x86_64
readonly node_name=node-22.22.2-linux-x86_64-v1
readonly zig_name=zig-0.16.0-linux-x86_64-v1
readonly node_source=node-22.22.2-linux-x86_64-v1
readonly zig_source=zig-0.16.0-linux-x86_64-v1

readonly node_url=https://nodejs.org/dist/v22.22.2/node-v22.22.2-linux-x64.tar.xz
readonly node_sha256=88fd1ce767091fd8d4a99fdb2356e98c819f93f3b1f8663853a2dee9b438068a
readonly zig_url=https://ziglang.org/download/0.16.0/zig-x86_64-linux-0.16.0.tar.xz
readonly zig_sha256=70e49664a74374b48b51e6f3fdfbf437f6395d42509050588bd49abe52ba3d00

readonly rustc_url=https://static.rust-lang.org/dist/2026-06-30/rustc-1.96.1-x86_64-unknown-linux-gnu.tar.xz
readonly rustc_sha256=3545a0efad2355ecb0a3b9ac02efee96e27f1f9d24b7ce2fc3f279b2efb0d923
readonly cargo_url=https://static.rust-lang.org/dist/2026-06-30/cargo-1.96.1-x86_64-unknown-linux-gnu.tar.xz
readonly cargo_sha256=ecc53a3c49fab5ab8c9301b3bbc8fb1dff9be6c65287add3f57a0fe8fddfea9e
readonly rust_std_url=https://static.rust-lang.org/dist/2026-06-30/rust-std-1.96.1-x86_64-unknown-linux-gnu.tar.xz
readonly rust_std_sha256=1bf4fde5048cca33e6ea00c7471281ed96d792f6923141e3db45072743a1afae
readonly clippy_url=https://static.rust-lang.org/dist/2026-06-30/clippy-1.96.1-x86_64-unknown-linux-gnu.tar.xz
readonly clippy_sha256=385644867534c30c490f4507d61485a799f81dfaec7e2a91290a41bf43d8286a
readonly rustfmt_url=https://static.rust-lang.org/dist/2026-06-30/rustfmt-1.96.1-x86_64-unknown-linux-gnu.tar.xz
readonly rustfmt_sha256=dcee5627f709f387cdca416a1d2ae9e6c2581cd117cdb4fd097c56c196384662

for command in chmod chown cp curl cut dirname find flock install jq mktemp rm sha256sum sort tar xz; do
  if ! command -v "$command" >/dev/null; then
    echo "ERROR: required bootstrap command is absent: $command" >&2
    exit 69
  fi
done
if [[ ! -x "$titanium" ]]; then
  echo "ERROR: the fixed rdashboard-titanium binary is not installed." >&2
  exit 69
fi

mapfile -t wrapper_inventory < <(
  find "$wrapper_root" -mindepth 1 -maxdepth 1 -printf '%f\n' | LC_ALL=C sort
)
if (( ${#wrapper_inventory[@]} != ${#wrappers[@]} )) \
  || [[ "${wrapper_inventory[*]}" != "${wrappers[*]}" ]]; then
  echo "ERROR: Titanium wrapper inventory differs from the exact rust-v1 interface." >&2
  exit 65
fi
for wrapper in "${wrappers[@]}"; do
  if [[ ! -f "$wrapper_root/$wrapper" || -L "$wrapper_root/$wrapper" || ! -x "$wrapper_root/$wrapper" ]]; then
    echo "ERROR: Titanium wrapper is not a fixed executable file: $wrapper" >&2
    exit 65
  fi
done

if [[ ! -e "$bootstrap_lock" ]]; then
  install -m 0600 /dev/null "$bootstrap_lock"
elif [[ ! -f "$bootstrap_lock" || -L "$bootstrap_lock" ]]; then
  echo "ERROR: Titanium bootstrap lock is not a fixed regular file." >&2
  exit 65
fi
chown root:root "$bootstrap_lock"
chmod 0600 "$bootstrap_lock"
exec 9<>"$bootstrap_lock"
if ! flock --nonblock 9; then
  echo "ERROR: another Rust Titanium bootstrap is already running." >&2
  exit 75
fi

if installed="$($titanium inspect-toolchain "$toolchain_name" "$target" rust-v1 2>/dev/null)"; then
  printf '%s\n' "$installed"
  exit 0
fi

work="$(mktemp -d "/var/lib/rdashboard-build/.bootstrap-${bootstrap_release}.XXXXXX")"
cleanup() {
  rm -rf -- "$work"
  rm -rf -- \
    "$import_root/$node_source" \
    "$import_root/$zig_source" \
    "$import_root/$toolchain_source"
}
trap cleanup EXIT
trap 'exit 129' HUP
trap 'exit 130' INT
trap 'exit 143' TERM

download() {
  local url="$1"
  local expected="$2"
  local output="$3"
  curl --fail --silent --show-error --location "$url" --output "$output"
  printf '%s  %s\n' "$expected" "$output" | sha256sum --check --status
}

seal_tree() {
  local root="$1"
  chown -R root:root "$root"
  find "$root" -type f ! -perm /0111 -exec chmod 0444 {} +
  find "$root" -type f -perm /0111 -exec chmod 0555 {} +
  find "$root" -type d -exec chmod 0555 {} +
}

copy_without_hardlinks() {
  local source="$1"
  local destination="$2"
  install -d -m 0755 "$destination"
  cp -a --no-preserve=links "$source"/. "$destination"/
}

node_digest="$($titanium inspect-artifact "$node_name" "$target" build-tool 2>/dev/null || true)"
if [[ -z "$node_digest" ]]; then
  node_import="$import_root/$node_source"
  rm -rf -- "$node_import"
  download "$node_url" "$node_sha256" "$work/node.tar.xz"
  install -d -m 0755 "$work/node-extract"
  tar --extract --xz --file="$work/node.tar.xz" --directory="$work/node-extract" --no-same-owner
  install -d -m 0755 "$node_import/bin"
  install -m 0755 \
    "$work/node-extract/node-v22.22.2-linux-x64/bin/node" \
    "$node_import/bin/node"
  seal_tree "$node_import"
  node_digest="$($titanium import-artifact \
    "$node_name" "$target" build-tool verified-upstream-prebuilt \
    "$node_sha256" "$node_source")"
fi

zig_digest="$($titanium inspect-artifact "$zig_name" "$target" build-tool 2>/dev/null || true)"
if [[ -z "$zig_digest" ]]; then
  zig_import="$import_root/$zig_source"
  rm -rf -- "$zig_import"
  download "$zig_url" "$zig_sha256" "$work/zig.tar.xz"
  install -d -m 0755 "$work/zig-extract"
  tar --extract --xz --file="$work/zig.tar.xz" --directory="$work/zig-extract" --no-same-owner
  copy_without_hardlinks "$work/zig-extract/zig-x86_64-linux-0.16.0" "$zig_import"
  seal_tree "$zig_import"
  zig_digest="$($titanium import-artifact \
    "$zig_name" "$target" build-tool verified-upstream-prebuilt \
    "$zig_sha256" "$zig_source")"
fi

toolchain_import="$import_root/$toolchain_source"
rm -rf -- "$toolchain_import"
install -d -m 0755 "$work/rust-archives" "$work/rust-extract" "$work/rust-root"
download "$rustc_url" "$rustc_sha256" "$work/rust-archives/rustc.tar.xz"
download "$cargo_url" "$cargo_sha256" "$work/rust-archives/cargo.tar.xz"
download "$rust_std_url" "$rust_std_sha256" "$work/rust-archives/rust-std.tar.xz"
download "$clippy_url" "$clippy_sha256" "$work/rust-archives/clippy.tar.xz"
download "$rustfmt_url" "$rustfmt_sha256" "$work/rust-archives/rustfmt.tar.xz"
for archive in "$work"/rust-archives/*.tar.xz; do
  tar --extract --xz --file="$archive" --directory="$work/rust-extract" --no-same-owner
done
for installer in "$work"/rust-extract/*/install.sh; do
  "$installer" --prefix="$work/rust-root" --disable-ldconfig
done

copy_without_hardlinks "$work/rust-root" "$toolchain_import"
install -d -m 0755 "$toolchain_import/node" "$toolchain_import/zig"
for wrapper in "${wrappers[@]}"; do
  install -m 0755 "$wrapper_root/$wrapper" "$toolchain_import/bin/$wrapper"
done

jq --compact-output --join-output --sort-keys --null-input \
  --arg node "$node_digest" \
  --arg zig "$zig_digest" \
  '{
      purpose: "rdashboard.titanium-toolchain.v1",
      schema_version: 1,
      interface: "rust-v1",
      target: "linux-x86_64",
      required_executables: [
        "ar", "c++", "cargo", "cargo-clippy", "cargo-fmt", "cc",
        "clippy-driver", "node", "ranlib", "rustc", "rustdoc", "rustfmt"
      ],
      components: [
        {mount: "node", artifact_digest: $node},
        {mount: "zig", artifact_digest: $zig}
      ]
  }' >"$toolchain_import/.titanium-toolchain.jcs"
seal_tree "$toolchain_import"

mapfile -t dependencies < <(printf '%s\n%s\n' "$node_digest" "$zig_digest" | sort)
toolchain_provenance="$({
  printf '%s\n' \
    "$cargo_sha256" "$clippy_sha256" "$rust_std_sha256" "$rustc_sha256" "$rustfmt_sha256"
  for wrapper in "${wrappers[@]}"; do
    printf '%s ' "$wrapper"
    sha256sum "$wrapper_root/$wrapper" | cut -d ' ' -f 1
  done
} | sha256sum | cut -d ' ' -f 1)"

toolchain_digest="$($titanium import-toolchain \
  "$toolchain_name" "$target" verified-upstream-prebuilt \
  "$toolchain_provenance" "$toolchain_source" "${dependencies[@]}")"
verified="$($titanium inspect-toolchain "$toolchain_name" "$target" rust-v1)"
if [[ "$verified" != "$toolchain_digest" ]]; then
  echo "ERROR: imported Titanium toolchain identity changed during inspection." >&2
  exit 70
fi

printf '%s\n' "$verified"
