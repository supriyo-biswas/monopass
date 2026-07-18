# monopass

monopass is a local-first password manager and credential storage daemon that stores data securely on your machine, protected with AES-256-GCM encryption.

## Key features

* **Bank-grade security:** Secure local data using AES-256-GCM encryption and PBKDF2 key derivation (256,000 iterations).
* **Single-binary deployment:** Run instantly on Linux and macOS with a single, dependency-free executable.
* **Seamless sharing:** Share credentials effortlessly with other users via `monopass share`.
* **Built-in TOTP:** Store and generate TOTP codes directly, replacing standalone authenticator apps.
* **Credential daemon:** Integrate any application via the [API](docs/specs/api-spec.md), bypassing the need for native system keyrings.
* **Automatic session caching:** Prevent repeated password prompts. Enter your master password once, and the requesting process chain is trusted for 15 minutes (configurable).
* **CLI-native:** Automate workflows easily by integrating the command-line interface directly into your scripts.

## Getting started

```sh
curl -fsSL https://raw.githubusercontent.com/supriyo-biswas/monopass/master/install.sh | sh
monopass init
```

## License

This project is licensed under the MIT license. See the [LICENSE file](LICENSE) for details.
