# `.env` files and references

It is common for many software projects to carry unencrypted secrets in their `.env` files, or worse, make use of hardcoded credentials. For local development, `monopass` provides a number of utilities to replace unencrypted secrets, as well as allowing you to run specific programs with said secrets.

For sharing local development secrets with other users in a team environment, see [sharing items](./05-sharing-items.md).

For production environments, you should continue to use a secret management system native to the deployment mechanism, such as [Kubernetes secrets](https://kubernetes.io/docs/concepts/configuration/secret/) or [AWS Secrets Manager](https://docs.aws.amazon.com/AmazonECS/latest/developerguide/secrets-envvar-secrets-manager.html).

For additional information on scripting use cases, see [chapter 6](./06-scripting-with-the-cli.md) and the [recipes](../../../README.md#recipes).

## Moving secrets from the `.env` file

Say you have a `.env` file used for local development with some secrets, such as:

```ini
APP_MODEL_ID=gpt-4o-mini
APP_CLIENT_CERT=dev/cert.pem
OPENAI_API_KEY=sk_9f47ad601c81fd4d1bfd50f69dc077d2
AWS_ACCESS_KEY_ID=AKIAIOSFODNN7EXAMPLE
AWS_SECRET_ACCESS_KEY=wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY
```

The `OPENAI_API_KEY`, `APP_CLIENT_CERT`, `AWS_ACCESS_KEY_ID` and `AWS_SECRET_ACCESS_KEY` are secrets and should be moved to monopass. Create a directory for your development secrets and store them there. In this example, we will store our secrets under `Work/MyAppDevSecrets`:

```sh
monopass mkdir -p Work
monopass add Work/MyAppDevSecrets \
    --field openai_api_key \
    --field aws_access_key_id \
    --field aws_secret_access_key \
    --concealed-fields openai_api_key,aws_secret_access_key \
    --file client_cert.pem=dev/cert.pem
```

Now, replace the values in the `.env` file with reference URLs, like so:

```ini
APP_MODEL_ID=gpt-4o-mini
APP_CLIENT_CERT=pass://Work/MyAppDevSecrets/client_cert.pem
OPENAI_API_KEY=pass://Work/MyAppDevSecrets/openai_api_key
AWS_ACCESS_KEY_ID=pass://Work/MyAppDevSecrets/aws_access_key_id
AWS_SECRET_ACCESS_KEY=pass://Work/MyAppDevSecrets/aws_secret_access_key
```

The `client_cert.pem` file is not needed any more, so feel free to delete it. If you've also stored these files in git, it may be best for you to rotate the secrets altogether, as it is difficult to fully delete an object from git history.

## Running processes with environment variables

Once these are in your environment variables, use the `monopass run` command to run programs that use those variables. For example, if your local development server is a Node-based project, you might use something like this:

```sh
monopass run -e .env npm run start
```

The application can then use these environment variables.

| Previous chapter | Next chapter |
| --- | --- |
| [Scripting with the CLI](06-scripting-with-the-cli.md) | [Integrating an application](08-integrate-an-application.md) |
