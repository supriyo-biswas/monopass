# monopass

monopass is a local-first password manager and credential storage daemon that stores data securely on your machine, protected with AES-256-GCM encryption.

## Key features

* **Bank-grade security:** Secure local data using AES-256-GCM encryption and PBKDF2 key derivation (256,000 iterations).
* **Single-binary installation:** Run on Linux, macOS, and Windows with one executable.
* **Seamless sharing:** Share credentials effortlessly with other users via `monopass share`.
* **Built-in TOTP:** Store and generate TOTP codes directly, replacing standalone authenticator apps.
* **Automatic session caching:** Prevent repeated password prompts. Enter your master password once, and the requesting process chain is trusted for 15 minutes (configurable).
* **CLI-native:** Automate workflows easily by integrating the command-line interface directly into your scripts.
* **Credential daemon:** Integrate any application via the [API](docs/user/guide/08-integrate-an-application.md), bypassing the need for native system keyrings.

## Quickstart

Use the commands below to get started, which will install monopass, configure shell completions, initialize your password vault, and auto-start the password agent.

```sh
curl -fsSL https://raw.githubusercontent.com/supriyo-biswas/monopass/master/install.sh | sh
monopass init
```

And then, add your first password and retrieve it:

```sh
monopass add Personal/GitHub --username my-username --password
monopass ls
monopass ls Personal
monopass show Personal/GitHub --reveal
```

## Documentation

### User guide

1. [Getting started](docs/user/guide/01-getting-started.md)
2. [Creating and editing directories and items](docs/user/guide/02-creating-dirs-and-items.md)
3. [Listing, moving, deleting and versioning items](docs/user/guide/03-listing-moving-deleting-versioning.md)
4. [Secure access to your vault](docs/user/guide/04-secure-access-to-your-vault.md)
5. [Sharing items](docs/user/guide/05-sharing-items.md)
6. [Connect existing tools](docs/user/guide/06-scripting-with-the-cli.md)
7. [`.env` files and references](docs/user/guide/07-env-files-and-references.md)
8. [Use the local agent API](docs/user/guide/08-integrate-an-application.md)

### Recipes

- [Using monopass as a git credential cache](docs/user/recipes/git-credential-cache.md)
- [Using monopass to store Ansible vault passwords](docs/user/recipes/ansible-vault.md)
- [Supply AWS CLI credentials from monopass](docs/user/recipes/aws-cli.md)

### References

- [Settings](docs/user/references/settings.md)
- [API reference](docs/user/references/api-reference.md)

## License

This project is licensed under the MIT license. See the [LICENSE file](LICENSE) for details.
