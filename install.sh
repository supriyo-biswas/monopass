#!/bin/sh

set -eu

REPO="supriyo-biswas/monopass"
DEFAULT_RELEASE_BASE_URL="https://github.com/${REPO}/releases/latest/download"
RELEASE_BASE_URL="${RELEASE_BASE_URL:-$DEFAULT_RELEASE_BASE_URL}"
INSTALL_DIR="${INSTALL_DIR:-$HOME/.local/bin}"
MONOPASS_VARIANT="${MONOPASS_VARIANT:-auto}"
BINARY_NAME="monopass"
PROFILE_LINE='export PATH="$HOME/.local/bin:$PATH"'

die() {
  printf 'monopass install: %s\n' "$*" >&2
  exit 1
}

need_cmd() {
  for requirement in "$@"; do
    found=0
    old_ifs=$IFS
    IFS=/

    for cmd in $requirement; do
      if command -v "$cmd" >/dev/null 2>&1; then
        found=1
        break
      fi
    done

    IFS=$old_ifs
    [ "$found" -eq 1 ] || die "required command not found: $requirement"
  done
}

download() {
  url=$1
  output=$2

  if command -v curl >/dev/null 2>&1; then
    curl -fL --progress-bar "$url" -o "$output"
  elif command -v wget >/dev/null 2>&1; then
    wget -qO "$output" "$url"
  else
    die "required command not found: curl or wget"
  fi
}

append_path_line() {
  profile=$1

  mkdir -p "$(dirname "$profile")"

  if [ -f "$profile" ] && grep -F "$PROFILE_LINE" "$profile" >/dev/null 2>&1; then
    return
  fi

  if [ -f "$profile" ]; then
    printf '\n%s\n' "$PROFILE_LINE" >> "$profile"
  else
    printf '%s\n' "$PROFILE_LINE" >> "$profile"
  fi
}

need_cmd curl/wget uname tar mktemp chmod mv mkdir grep dirname rm id

platform="$(uname -sm | tr '[:upper:]' '[:lower:]' | tr ' ' '-')"
selected_variant=cli

case "$platform" in
  linux-x86_64|linux-amd64)
    platform=linux-x86_64
    ;;
  linux-aarch64|linux-arm64)
    platform=linux-aarch64
    ;;
  darwin-arm64)
    ;;
  *)
    die "unsupported platform: $platform"
    ;;
esac

case "$platform" in
  linux-*)
    case "$MONOPASS_VARIANT" in
      auto|gtk|qt|cli)
        selected_variant=$MONOPASS_VARIANT
        ;;
      *)
        die "invalid MONOPASS_VARIANT: $MONOPASS_VARIANT (expected auto, gtk, qt, or cli)"
        ;;
    esac

    if [ "$selected_variant" = auto ]; then
      desktop="$(printf '%s' "${XDG_CURRENT_DESKTOP:-}" | tr '[:upper:]' '[:lower:]')"
      case "$desktop" in
        *kde*|*plasma*|*lxqt*)
          selected_variant=qt
          ;;
        ?*)
          selected_variant=gtk
          ;;
        *)
          selected_variant=cli
          ;;
      esac
    fi
    ;;
esac

case "$selected_variant" in
  cli)
    artifact_name="monopass-$platform.tar.gz"
    ;;
  *)
    artifact_name="monopass-$platform-$selected_variant.tar.gz"
    ;;
esac

path_was_missing=0
case ":${PATH:-}:" in
  *:"$HOME/.local/bin":*)
    ;;
  *)
    path_was_missing=1
    ;;
esac

tmp_dir="$(mktemp -d)"
cleanup() {
  rm -rf "$tmp_dir"
}
trap cleanup EXIT HUP INT TERM

archive_path="$tmp_dir/$artifact_name"
download_url="$RELEASE_BASE_URL/$artifact_name"

printf 'Selected %s variant for %s.\n' "$selected_variant" "$platform" >&2
printf 'Downloading %s\n' "$download_url" >&2
download "$download_url" "$archive_path" || die "failed to download $artifact_name"

tar -xzf "$archive_path" -C "$tmp_dir" || die "failed to unpack $artifact_name"

if [ ! -f "$tmp_dir/$BINARY_NAME" ]; then
  die "archive did not contain $BINARY_NAME"
fi

mkdir -p "$INSTALL_DIR"

chmod 755 "$tmp_dir/$BINARY_NAME"
mv -f "$tmp_dir/$BINARY_NAME" "$INSTALL_DIR/$BINARY_NAME"

profiles=.profile

case "${SHELL:-}" in
  */bash)
    profiles="$profiles .bashrc .bash_profile"
    ;;
  */zsh)
    profiles="$profiles .zshrc .zprofile"
    ;;
esac

for profile in $profiles; do
  append_path_line "$HOME/$profile"
done

restart_existing_agent() {
  case "$platform" in
    linux-*)
      if ! command -v systemctl >/dev/null 2>&1; then
        return 0
      fi

      if ! systemctl --user status monopass-agent.socket >/dev/null 2>&1; then
        return 0
      fi

      systemctl --user stop monopass-agent.service monopass-agent.socket >/dev/null 2>&1 || true
      systemctl --user start monopass-agent.socket >/dev/null 2>&1 || true
      ;;
    darwin-arm64)
      uid="$(id -u)"
      domain_label="gui/$uid"
      service_target="$domain_label/com.monopass.agent"
      plist="$HOME/Library/LaunchAgents/com.monopass.agent.plist"

      launchctl print "$service_target" >/dev/null 2>&1 || return 0
      [ -f "$plist" ] || return 0

      launchctl bootout "$service_target" >/dev/null 2>&1 || true
      launchctl bootstrap "$domain_label" "$plist" >/dev/null 2>&1 || true
      launchctl enable "$service_target" >/dev/null 2>&1 || true
      launchctl kickstart -k "$service_target" >/dev/null 2>&1 || true
      ;;
  esac
}

restart_existing_agent

printf 'Installed %s to %s/%s\n' "$BINARY_NAME" "$INSTALL_DIR" "$BINARY_NAME" >&2

if [ "$path_was_missing" -eq 1 ]; then
  case "${SHELL:-}" in
    */bash)
      printf 'Add %s to your PATH in a new shell, or run: . ~/.bashrc\n' "$HOME/.local/bin" >&2
      ;;
    */zsh)
      printf 'Add %s to your PATH in a new shell, or run: . ~/.zshrc\n' "$HOME/.local/bin" >&2
      ;;
    *)
      printf 'Add %s to your PATH in a new shell to pick up the change.\n' "$HOME/.local/bin" >&2
      ;;
  esac
fi
