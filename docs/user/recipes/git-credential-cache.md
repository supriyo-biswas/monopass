# Using monopass as a git credential cache

By default, git asks your username and password for all authenticated operations. To avoid this, you can use monopass as a credential helper.

## Install the helper

Save this script as `~/.local/bin/git-credential-monopass`:

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
        if [ "$have_username" = true ] &&
            item_exists "${credential_base}_${username}"; then
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
            [ "$have_username" = true ] &&
                [ "$have_password" = true ] || exit 0
            printf '%s\n' "$password" |
                monopass add "$credential_path" \
                    --username "$username" \
                    --field password \
                    --concealed-fields password
        fi
        ;;
    erase)
        credential_path=$credential_base
        if [ "$have_username" = true ] &&
            item_exists "${credential_base}_${username}"; then
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

Make the helper private and executable, create its item directory, and register it globally:

```sh
chmod 700 "$HOME/.local/bin/git-credential-monopass"
monopass mkdir -p GitCredentials
git config --global credential.helper \
    "$HOME/.local/bin/git-credential-monopass"
```

## Let Git store the first token

On the next authenticated fetch, enter your username and token:

```
$ git fetch origin
Username for 'https://github.com': your-name
Password for 'https://your-name@github.com':
From https://github.com/acme/deploy
 * [new branch]      main       -> origin/main
```

Git passes both values to the helper on stdin. The helper stores a concealed
item that you can inspect safely:

```
$ monopass show GitCredentials/https_github.com_your-name
Name: https_github.com_your-name
Created: 2026-07-25T11:07:31Z
Updated: 2026-07-25T11:07:31Z
Versions: 1
Fields:
  password: ******
  username: your-name
```

A later fetch retrieves the credential without prompting:

```
$ git fetch origin
# no output: the repository was already current
```

## Limit the helper to one repository

The setup above applies globally. To scope it to one repository, remove the
global entry, enter the repository, and configure a local absolute helper path:

```sh
git config --global --unset-all credential.helper
cd "$HOME/src/acme-deploy"
git config --local credential.helper \
    "$HOME/.local/bin/git-credential-monopass"
```
