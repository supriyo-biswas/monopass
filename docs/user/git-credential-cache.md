# Git credential helper

`git-credential-monopass` lets Git store and retrieve HTTPS credentials through
the monopass agent. Copy the following script to
`~/.local/bin/git-credential-monopass`:

```sh
#!/bin/sh
set -eu

action=${1:-get}

protocol=https
host=
username=
password=
have_username=false
have_password=false

while IFS='=' read -r key value; do
    [ -n "$key" ] || break

    case "$key" in
        protocol) protocol=$value ;;
        host) host=$value ;;
        username) username=$value; have_username=true ;;
        password) password=$value; have_password=true ;;
    esac
done

[ -n "$host" ] || exit 0

credential_base="GitCredentials/${protocol}_${host}"

item_exists() {
    [ -n "$(monopass ls --globoff "$1")" ]
}

case "$action" in
    get)
        credential_path=$credential_base
        if [ "$have_username" = true ] && item_exists "${credential_base}_${username}"; then
            credential_path="${credential_base}_${username}"
        elif ! item_exists "$credential_base"; then
            exit 0
        fi
        username=$(monopass read "$credential_path/username")
        password=$(monopass read "$credential_path/password")
        printf 'username=%s\npassword=%s\n\n' "$username" "$password"
        ;;
    store)
        credential_path=$credential_base
        if [ "$have_username" = true ]; then
            credential_path="${credential_base}_${username}"
        fi
        if item_exists "$credential_path"; then
            set -- monopass edit "$credential_path"
            changed=false
            if [ "$have_username" = true ]; then
                set -- "$@" --username "$username"
                changed=true
            fi
            if [ "$have_password" = true ]; then
                set -- "$@" --field password --concealed-fields password
                changed=true
            fi
            if [ "$changed" = true ]; then
                if [ "$have_password" = true ]; then
                    printf '%s\n' "$password" | "$@"
                else
                    "$@"
                fi
            fi
        else
            [ "$have_username" = true ] && [ "$have_password" = true ] || exit 0
            printf '%s\n' "$password" | monopass add "$credential_path" \
                --username "$username" \
                --field password \
                --concealed-fields password
        fi
        ;;
    erase)
        credential_path=$credential_base
        if [ "$have_username" = true ] && item_exists "${credential_base}_${username}"; then
            credential_path="${credential_base}_${username}"
        elif ! item_exists "$credential_base"; then
            exit 0
        fi
        monopass rm --globoff "$credential_path"
        ;;
    *)
        exit 0
        ;;
esac
```

Make the helper executable, create its default directory, and register it
globally with Git:

```sh
mkdir -p ~/.local/bin
chmod 700 ~/.local/bin/git-credential-monopass
monopass mkdir -p GitCredentials
git config --global credential.helper "$HOME/.local/bin/git-credential-monopass"
```

Verify the registration with:

```sh
git config --global --get-all credential.helper
```

On the first authenticated Git operation, Git prompts for the username and
password and asks the helper to store them. By default, an HTTPS credential for
the GitHub username `supriyo-biswas` is stored as
`GitCredentials/https_github.com_supriyo-biswas`, with fields named `username`
and `password`. Later operations read those fields automatically.

Git maps `get` to field reads, `store` to item creation or editing, and `erase`
to a normal removal that moves the item to `Trash` for recovery. Credentials are
saved in the `GitCredentials` directory; change that name in `credential_base`
in the script if you prefer another directory.

When Git supplies a username, the helper first looks for the username-specific
item and then falls back to the legacy host-only item, such as
`GitCredentials/https_github.com`. Stores use the username-specific item. Erase
removes it when present, or removes the host-only fallback otherwise.

To configure the helper for only one repository, run the `git config` command
without `--global` from that repository.
