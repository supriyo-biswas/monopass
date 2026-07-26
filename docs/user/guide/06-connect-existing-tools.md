# Connect existing tools

You have a variety of ways of integrating monopass with other command line tools. This chapter discusses a few of them.

While the earlier chapters describe commands like `ls`, `cp`, and `mv`, which already provide a surface for CLI integration, there are a few other commands that make scripting much easier. In addition, there are a few [recipes](#recipes) that you can use for easy integration with industry-standard tools, bypassing the need for custom scripts.

## Retrieve an item as JSON

To retrieve the individual fields of an item, it is often preferable to use the JSON format. For example, to list the fields and files of the `Work/AcmeDeploy` item, use:

```sh
monopass show Work/AcmeDeploy --format json
```

This will print a JSON-formatted view, like this:

```json
{"name":"AcmeDeploy","created_at":"2026-07-25T09:42:17Z","updated_at":"2026-07-25T09:42:17Z","total_versions":1,"fields":[{"name":"api_token","type":"string","concealed":true,"data":"***"},{"name":"database_url","type":"string","concealed":true,"data":"***"}],"files":[{"name":"client_cert","size":1184}]}
```

Just as with the original show command, the concealed fields are masked, and you can use `--reveal` to show the values.

## Read a single field or file

Often, you may want to read a single field only without retrieving all fields using the `show --format json` command. In addition, the `show` command does not provide a way to access files. In these cases, you can use the `monopass read <directory>/<item>/<fieldOrFileName>` command, which will print the content of that field or file.

Continuing with our `Work/AcmeDeploy` example above, we show an example of how we can read the `api_token` field and the `client_cert` file:

```
$ monopass read Work/AcmeDeploy/api_token
ghp_qxsg1287b93kumrgqj5hh88v9u1eul4u

$ monopass read Work/AcmeDeploy/client_cert
-----BEGIN PRIVATE KEY-----
MIIEvgIBADANBgkqhkiG9w0BAQEFAASCBKgwggSkAgEAAoIBAQDBj08sp5++4anG
...
```

You can use this to retrieve files and fields for scripting use cases, though we **strongly discourage** such uses in favor of using [`monopass run`](#monopass-run).

As an example, imagine you have a `deploy-aws.sh` script that performs operations on AWS; you may want to read the access and secret key like so:

```sh
export AWS_ACCESS_KEY_ID=$(monopass read Work/AWSProdDeployKey/aws_access_key_id)
export AWS_SECRET_ACCESS_KEY=$(monopass read Work/AWSProdDeployKey/aws_secret_access_key)

# AWS_ACCESS_KEY_ID and AWS_SECRET_ACCESS_KEY are recognized by `aws`
aws ec2 create-instance ...
```

When reading a file from monopass, remember to set up a [`trap`](https://tldp.org/LDP/Bash-Beginners-Guide/html/sect_12_02.html) so that the file is cleaned up after the script exits. The example below shows how to drive the Google Cloud CLI by reading the application credentials file from monopass and configuring the environment variable.

```sh
export GOOGLE_APPLICATION_CREDENTIALS=$(mktemp /tmp/XXXXX.json)

# configure cleanup when the process exits
trap 'rm -f $GOOGLE_APPLICATION_CREDENTIALS || true' EXIT INT TERM HUP ERR

# /tmp/<randomId>.json contains the credentials, and
# GOOGLE_APPLICATION_CREDENTIALS=/tmp/<randomId>.json
monopass read Work/GoogleProdDeployKey/credentials.json -o $GOOGLE_APPLICATION_CREDENTIALS

# GOOGLE_APPLICATION_CREDENTIALS is recognized by `gcloud`
gcloud compute images ...
```

## `monopass run`

For improved security, you may want to let monopass handle launching the program with environment variables and files. This can be done using `monopass run`.

You begin by setting up environment variables with reference URLs in your script, which are of the form `pass://<directory>/<itemName>/<fieldOrFileName>`. `monopass run` replaces field references with their values in the environment variables. For files, it writes them to a temporary path and sets that path in the environment variable.

Rewriting our examples to use `monopass run`, you can do something like this:

```sh
export AWS_ACCESS_KEY_ID=pass://Work/AWSProdDeployKey/aws_access_key_id
export AWS_SECRET_ACCESS_KEY=pass://Work/AWSProdDeployKey/aws_secret_access_key

monopass run aws ec2 create-instance ...
```

Similarly, in the `gcloud` case, you can refer to a file:

```sh
export GOOGLE_APPLICATION_CREDENTIALS=pass://Work/GoogleProdDeployKey/credentials.json

monopass run gcloud compute images ...
```

You can also use this with a `.env` file; see [chapter 7](./07-env-files-and-references.md) for an example. 1Password-style references using `op://` instead of `pass://` are also understood.

## Recipes

Refer to the following recipes to learn how to integrate monopass with industry-standard tools:

- [Git credential provider](../recipes/git-credential-cache.md): A helper that integrates with `git` to store credentials securely.
- [Ansible Vault integration](../recipes/ansible-vault.md) for encrypting Ansible secrets using a vault password.
- [AWS CLI external process integration](../recipes/aws-cli.md), to store credentials in monopass instead of `aws configure`, which uses plaintext.

| Previous chapter | Next chapter |
| --- | --- |
| [Sharing items](05-sharing-items.md) | [`.env` files and references](07-env-files-and-references.md) |
