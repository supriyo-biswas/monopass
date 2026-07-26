# Using monopass to store Ansible vault passwords

When working with Ansible Vault, you need to provide your vault passwords to Ansible so that it can encrypt and decrypt the secrets for storing them in inventory files. You can use monopass as the storage mechanism for these vault passwords.

## Install the helper

Save this script as `~/.local/bin/monopass-vault-client`:

```sh
#!/bin/sh
set -eu

vault_id=
while [ "$#" -gt 0 ]; do
    case "$1" in
        --vault-id)
            [ "$#" -ge 2 ] || {
                printf '%s\n' 'missing value for --vault-id' >&2
                exit 2
            }
            vault_id=$2
            shift 2
            ;;
        --vault-id=*)
            vault_id=${1#--vault-id=}
            shift
            ;;
        *)
            printf 'unsupported argument: %s\n' "$1" >&2
            exit 2
            ;;
    esac
done

[ -n "$vault_id" ] || vault_id=default

case "$vault_id" in
    */* | . | ..)
        printf 'unsupported vault id: %s\n' "$vault_id" >&2
        exit 2
        ;;
esac

exec monopass read "pass://AnsibleVault/$vault_id/password"
```

Make the helper private and executable:

```sh
chmod 700 "$HOME/.local/bin/monopass-vault-client"
```

The commands below refer to the helper by name, so make sure
`~/.local/bin` is in your `PATH`. The helper also needs to be able to find the
`monopass` command.

Ansible invokes the helper with the Vault ID you provide. The helper writes only the selected vault password to stdout; monopass prompts and errors stay off that output.

## Save your vault password

For each vault that you have, save the password in the `AnsibleVault` directory:

```sh
monopass add AnsibleVault/dev --password
```

For an unlabeled Vault, create `AnsibleVault/default` with a `password` field, then configure the helper as Ansible's default password source:

```sh
monopass add AnsibleVault/default --password
export ANSIBLE_VAULT_PASSWORD_FILE=monopass-vault-client
```

## Encrypt and run with Vault IDs

You can now point each Ansible command to `monopass-vault-client`. For example, to encrypt values in an inventory with the vault named `dev`, you would use:

```sh
ansible-vault encrypt --vault-id "dev@monopass-vault-client" group_vars/dev.yml
```

Similarly, to run an Ansible playbook with encrypted values, you would use:

```bash
ansible-playbook \
    --vault-id "dev@monopass-vault-client" \
    --vault-id "prod@monopass-vault-client" \
    deploy.yml
```
