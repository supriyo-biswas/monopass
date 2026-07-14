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

credential_path="GitCredentials/${protocol}_${host}"

item_exists() {
    [ -n "$(monopass ls --globoff "$credential_path")" ]
}

case "$action" in
    get)
        item_exists || exit 0
        username=$(monopass read "$credential_path/username")
        password=$(monopass read "$credential_path/password")
        printf 'username=%s\npassword=%s\n\n' "$username" "$password"
        ;;
    store)
        if item_exists; then
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
`github.com` is stored as `GitCredentials/https_github.com`, with fields named
`username` and `password`. Later operations read those fields automatically.

Git maps `get` to field reads, `store` to item creation or editing, and `erase`
to a normal removal that moves the item to `Trash` for recovery. Credentials are
saved in the `GitCredentials` directory; change that name in `credential_path`
in the script if you prefer another directory.

To configure the helper for only one repository, run the `git config` command
without `--global` from that repository.
