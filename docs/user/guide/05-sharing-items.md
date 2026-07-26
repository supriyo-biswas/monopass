# Sharing items

Sometimes you may need to share credentials with others who use monopass, such as to share common secrets for development in a team environment. This guide will walk you through that process.

We'll use two users, Alice and Bob, for our example; Alice is sharing a credential with Bob. Their terminals are marked `alice$` and `bob$` to distinguish the two.

## How does sharing work?

monopass internally maintains [age](https://github.com/filosottile/age)-based public and private keys. In a [public-key cryptosystem](https://en.wikipedia.org/wiki/Public-key_cryptography), you share your public key with other people, and others can send data to you by encrypting it with your public key. However, only you may decrypt such encrypted data using your private key.

At a high level, these are the steps that Alice and Bob undertake:

1. Bob shares his public key with Alice.
2. Alice encrypts an item with Bob's public key and shares it with Bob.
3. Bob decrypts the encrypted item and imports it into the monopass database.

## Bob shares his public key

Bob runs the `monopass pubkey` command to retrieve his public key:

```
bob$ monopass pubkey
age1ysxuaeqlk7xd8uqsh8lsnfwt9jzzjlqf49ruhpjrrj5yatlcuf7qke4pqe
```

He then shares the public key `age...` with Alice over a channel like email, Slack, etc.

## Alice shares the encrypted item with Bob

Alice first adds Bob as a contact:

```
alice$ monopass add-contact bob@example.com \
    age1ysxuaeqlk7xd8uqsh8lsnfwt9jzzjlqf49ruhpjrrj5yatlcuf7qke4pqe \
    --name Bob

alice$ monopass share Work/AcmeDeploy bob@example.com \
    --out-file ./AcmeDeploy-for-Bob.export
./AcmeDeploy-for-Bob.export
```

Alice then sends the encrypted `AcmeDeploy-for-Bob.export` file to Bob.

## Bob imports the credential

Bob receives the file that Alice sent, and imports it in his monopass instance by running `monopass import`. He can then view the item using `monopass show`:

```
bob$ monopass import Work/AcmeDeploy ./AcmeDeploy-for-Bob.export
bob$ monopass show Work/AcmeDeploy
Name: AcmeDeploy
Created: 2026-07-25T10:21:44Z
Updated: 2026-07-25T10:21:44Z
Versions: 1
Fields:
  api_token: ******
```

| Previous chapter | Next chapter |
| --- | --- |
| [Securing access to your vault](04-secure-access-to-your-vault.md) | [Connecting existing tools](06-connect-existing-tools.md) |
