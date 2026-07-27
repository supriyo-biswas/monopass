# Scripting with the CLI

You have a variety of ways of integrating monopass with other command line tools. This chapter discusses a few of them.

While the earlier chapters describe commands like `ls`, `cp`, and `mv`, which already provide a surface for CLI integration, we'll note some additional features that make scripting much easier.

Be sure to check the [recipes](../../../README.md#recipes) to see if there's an existing integration that you can use, bypassing the need for a custom script.

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

## Piping secrets to `add` or `edit`

When driving the `add` or `edit` commands via scripting, you might need to pipe in secrets from elsewhere. These commands accept inputs from stdin in the same order as the `--field` flags. You should mark any concealed fields with `--concealed-fields`, and the use of `--password` is discouraged because it only accepts input from a TTY.

As an example, if you want to save a username and password from a script into an item called Personal/GitHub, with the `username`, `email` and `password` fields, and these values are coming from stdin, you might do something like:

```sh
printf '%s\n%s\n%s' \
    my.user \
    my.email@example.com \
    MySuperStrongPassw0rd \
    | monopass add Personal/GitHub \
        --field username \
        --field email \
        --field password \
        --concealed-fields password
```

For a more practical example, consider the `aws iam create-access-key --user-name myuser` command, which returns values like this:

```json
{
    "AccessKey": {
        "UserName": "myuser",
        "AccessKeyId": "AKIAIOSFODNN7EXAMPLE",
        "Status": "Active",
        "SecretAccessKey": "wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY",
        "CreateDate": "2026-07-27T10:15:00Z"
    }
}
```

Let's say you're interested in saving the `AccessKeyId` and `SecretAccessKey` values. Begin by transforming the JSON into a series of lines. This can be done with `jq`:

```
$ aws iam create-access-key --user-name myuser | \
    jq -r '.AccessKey.AccessKeyId + "\n" + .AccessKey.SecretAccessKey'
AKIAIOSFODNN7EXAMPLE
wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY
```

You can now save this in monopass using the following command:

```sh
aws iam create-access-key --user-name myuser | \
    jq -r '.AccessKey.AccessKeyId + "\n" + .AccessKey.SecretAccessKey' | \
    monopass add Personal/AWSAccessKey \
        --field aws_access_key_id \
        --field aws_secret_access_key \
        --concealed-fields aws_secret_access_key
```

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

# `aws` expects credentials to be passed via AWS_ACCESS_KEY_ID and AWS_SECRET_ACCESS_KEY
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

# `gcloud` expects the GOOGLE_APPLICATION_CREDENTIALS to be the path to a credentials file
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

| Previous chapter | Next chapter |
| --- | --- |
| [Sharing items](05-sharing-items.md) | [`.env` files and references](07-env-files-and-references.md) |
