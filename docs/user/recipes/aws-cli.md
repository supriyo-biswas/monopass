# Supply AWS CLI credentials from monopass

You can have the [AWS CLI](https://aws.amazon.com/cli/) fetch access keys and secret keys from monopass instead of using the `~/.aws/credentials` file.

## Install the helper

Install the following helper in `~/.local/bin/aws_mp.sh`. It accepts one argument: the path to the item that contains the credentials.

```sh
#!/bin/sh

access_key=$(monopass read "$1/aws_access_key_id")
secret_key=$(monopass read "$1/aws_secret_access_key")

cat << EOM
{
  "Version": 1,
  "AccessKeyId": "$access_key",
  "SecretAccessKey": "$secret_key"
}
EOM
```

Make the helper private and executable:

```sh
chmod 700 "$HOME/.local/bin/aws_mp.sh"
```

And then, register the helper in `~/.aws/config`. Use `default` if you run the AWS command without a `--profile` flag. Replace `/home/me` with your home directory.

```ini
[default]
credential_process = /home/me/.local/bin/aws_mp.sh Personal/AWSAccessKey
```

Otherwise, use the name of the profile that you generally use. For example, if you have a profile named `staging`, you would use:

```ini
[profile staging]
credential_process = /home/me/.local/bin/aws_mp.sh Personal/AWSAccessKey
```

Because we've configured it to retrieve the `AWSAccessKey` item from the `Personal` vault, you'll need to create an item in the same location:

```sh
monopass add Personal/AWSAccessKey \
    --field aws_access_key_id=AKIAIOSFODNN7EXAMPLE \
    --field aws_secret_access_key \
    --concealed-fields aws_secret_access_key
```

## Run AWS CLI

Now run the `aws sts get-caller-identity` command to ensure that the AWS user is indeed the one you expect. If you see successful output, this confirms that the integration was configured successfully.

```
$ aws sts get-caller-identity
{
    "UserId": "AKIAIOSFODNN7EXAMPLE",
    "Account": "123456789012",
    "Arn": "arn:aws:iam::123456789012:user/developer"
}
```
