# Creating and editing directories and items

Once you've installed monopass, you'll want to start saving your credentials in it. This document will walk you through that process.

## Creating directories

monopass allows you to create _directories_ (or folders), inside of which you store _items_; each item holds details like your username and password. In other words, monopass allows you to group together items under a directory. By default, there's a default directory called `Personal`.

To list your directories, use:

```sh
monopass ls
```

This will print out the directory list; if you're a new user you'll see the default directory.

```
$ monopass ls
Personal
```

You can create other directories using the `mkdir` command, for example to create a directory named `Work`, use:

```sh
monopass mkdir Work
```

You can now see that there are two directories:

```
$ monopass ls
Personal
Work
```

Unlike filesystem regular files and directories, you cannot create directories inside of directories; they are strictly single-level only.

## Create an item

You can save a new item using `monopass add`. For example, if you're signing up for a website, you may want to store your username, email, and an auto-generated, secure password using:

```sh
monopass add Personal/GitHub \
  --username my-username \
  --email my-username@gmail.com \
  --generate-password
```

There is no output when the command is successful. To see the item, use `monopass show Personal/GitHub`.

```
$ monopass show Personal/GitHub
Name: GitHub
Created: 2026-07-25T16:16:20Z
Updated: 2026-07-25T16:16:20Z
Versions: 1
Fields:
  email: my-username@gmail.com
  password: ******
  username: my-username
```

On the other hand, if you want to provide the password yourself, use the `--password` flag instead of `--generate-password`, like so:

```sh
monopass add Personal/GitHub \
  --username my-username \
  --email my-username@gmail.com \
  --password
```

You'll be asked to type in the password twice, and the password entry won't be shown to you to prevent someone from snooping.

By default, secret fields like your password are concealed. However, you will sometimes need to see sensitive fields like your password, and you can do this using the `--reveal` flag:

```
$ monopass show Personal/GitHub --reveal
Name: GitHub
Created: 2026-07-25T16:16:20Z
Updated: 2026-07-25T16:16:20Z
Versions: 1
Fields:
  email: my-username@gmail.com
  password: Precision-Claw-Ecosphere_2
  username: my-username
```

Since the item was created in the `Personal` directory, it'll show up when you list it using `monopass ls Personal`:

```
$ monopass ls Personal
GitHub
```

## Adding custom fields to an item

Sometimes, you may want to store credentials that have custom fields, instead of the default fields like a username and password. For this purpose, you may use the `--field` and `--concealed-fields` options.

For example, [AWS access keys](https://docs.aws.amazon.com/IAM/latest/UserGuide/id_credentials_access-keys.html) consist of two parts: an "access key ID" that identifies the user, similar to a username, and a "secret access key" that should remain secret, like a password. To save this as an item with custom fields, use the `--field` flag and `--concealed-fields` to tell monopass which fields are secret:

```sh
monopass add "Personal/AWS Access Key" \
  --field aws_access_key_id \
  --field aws_secret_access_key \
  --concealed-fields aws_secret_access_key
```

You'll see prompts for the access key and secret key; the input for the secret key will be hidden just like our password was in the previous example.

Later, you can view the item:

```
$ monopass show "Personal/AWS Access Key" --reveal
Name: AWS Access Key
Created: 2026-07-25T17:01:53Z
Updated: 2026-07-25T17:01:53Z
Versions: 1
Fields:
  aws_access_key_id: AKIAIOSFODNN7EXAMPLE
  aws_secret_access_key: wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY
```

You can also provide a field directly on the command line, by using something like:

```sh
monopass add "Personal/AWS Access Key" \
  --field aws_access_key_id=AKIAIOSFODNN7EXAMPLE \
  --field aws_secret_access_key \
  --concealed-fields aws_secret_access_key
```

You can combine `--field` with regular fields like `--username` and `--password`. For example, you could do:

```sh
monopass add Personal/Shodan \
  --username my.username \
  --password \
  --field api_key \
  --concealed-fields api_key
```

This will create a concealed `username` and `api_key` field, but leave the username visible:

```
$ monopass show Personal/Shodan
Name: Shodan
Created: 2026-07-25T17:21:07Z
Updated: 2026-07-25T17:21:07Z
Versions: 1
Fields:
  api_key: ******
  password: ******
  username: my.username
```

## Copying items to the clipboard

To copy an item to the clipboard without revealing the whole item, use `monopass clip`. For example, to copy the password field of the GitHub item, you'd use:

```sh
monopass clip Personal/GitHub/password
```

On Linux, this requires the `xclip` command to be installed. The `clip` command is unavailable on the Linux CLI variant, as headless Linux installations do not have a clipboard to work with.

In the rest of this guide, we will continue using the `monopass show` command, but it is safer to copy passwords instead, as this does not display them on the screen for other people to snoop.

## Editing an item

You can edit an existing item by using `monopass edit`. For example, to create a new auto-generated password, you may use:

```sh
monopass edit Personal/GitHub --generate-password
```

Even though no output is shown, the item was saved successfully. You can then retrieve the new password using `monopass show`. Note that the number of versions increased from 1 to 2, confirming that the old version was overwritten:

```
$ monopass show Personal/GitHub --reveal
Name: GitHub
Created: 2026-07-25T16:16:20Z
Updated: 2026-07-25T17:15:04Z
Versions: 2
Fields:
  email: my-username@gmail.com
  password: Attitude-Enchilada-Relay@5
  username: my-username
```

As you can see, other fields were kept as-is. To remove a field, use the `--remove-fields` flag. For example, to remove the email from our GitHub example, while generating a new password, you would use:

```sh
monopass edit Personal/GitHub \
  --generate-password \
  --remove-fields email
```

This regenerates the password and removes the email field.

```
$ monopass show Personal/GitHub --reveal
Name: GitHub
Created: 2026-07-25T16:16:20Z
Updated: 2026-07-25T17:15:04Z
Versions: 2
Fields:
  password: Attitude-Enchilada-Relay@5
  username: my-username
```

## Auto-generating a password with various requirements

Sometimes, you want to generate a password, but with certain length or character requirements. While the default is a diceware-style password with three words followed by a symbol and a number, you can specify the requirements to the `add` or `edit` commands.

For example, to update the `Personal/GitHub` item with a new 32-character password with uppercase and lowercase letters, digits, and symbols, you'd use:

```sh
monopass edit Personal/GitHub \
  --generate-password '32,upper,lower,digits,symbols'
```

This will create an item that looks like this:

```
$ monopass show Personal/GitHub --reveal
Name: GitHub
Created: 2026-07-25T09:18:41Z
Updated: 2026-07-25T09:31:52Z
Versions: 3
Fields:
  password: uG7!mK2@qR8#vN4$xP9^cL6&zT3*
  username: your.name
```

Custom generator specifications begin with a length and a list of character sets, which can be `upper`, `lower`, `digit`/`digits`, `alpha`, `hex`, and `symbol`/`symbols`.

## Adding two-factor authentication

Many websites support [TOTP](https://en.wikipedia.org/wiki/Time-based_one-time_password)-based authentication. In such cases, you can pass the QR code using the `--totp` flag in the `add` or `edit` commands like so:

```sh
monopass edit Personal/GitHub --totp ./github-totp.png
```

As the TOTP is sensitive, remember to delete it after you're done!

```sh
rm ./github-totp.png
```

The next time you sign in, run `monopass show Personal/GitHub`. It will have the TOTP field, which is concealed by default unless you pass `--reveal`.

```
$ monopass show Personal/GitHub --reveal
Name: GitHub
Created: 2026-07-25T09:18:41Z
Updated: 2026-07-25T09:31:52Z
Versions: 3
Fields:
  password: uG7!mK2@qR8#vN4$xP9^cL6&zT3*
  totp: 384921
  username: your.name
```

You can also pass an `otpauth://`-style URL to the `--totp` flag; however, providing the image path is safer because it does not expose the TOTP details in the command-line arguments, where other processes could see them.

## Attaching files

You can also add files to an item in monopass using the `--file` flag; the provided file will be securely stored within monopass. For example, to store a copy of a receipt, you could do:

```sh
monopass add Personal/Chase \
  --username my.username \
  --generate-password \
  --file /home/me/Downloads/receipt.pdf
```

You can view the item, which will show that the file is attached:

```
$ monopass show Personal/Chase
Name: Chase
Created: 2026-07-25T18:13:13Z
Updated: 2026-07-25T18:13:13Z
Versions: 1
Fields:
  password: ******
  username: my.username
Files:
  receipt.pdf [95.2 KB]
```

If you want to store the file under a different name, use the `key=value` syntax. This command attaches the `receipt.pdf` file in your `Downloads` directory as `details.pdf` on the item:

```sh
monopass add Personal/Chase \
  --username my.username \
  --generate-password \
  --file details.pdf=/home/me/Downloads/receipt.pdf
```

You can similarly edit an item to add a file, or remove a file using the `edit` command. For example, to remove the file named `receipt.pdf` and add `credit_card_info.pdf`, you'd use:

```sh
monopass edit Personal/Chase \
  --file /home/me/Downloads/credit_card_info.pdf \
  --remove-file receipt.pdf
```

To retrieve the file `receipt.pdf` from the `Personal/Chase` item in your current directory under the same name, use the following command:

```sh
monopass read Personal/Chase/receipt.pdf -o receipt.pdf
```

By default, monopass creates the file with 0600 permissions, to prevent other system users from reading the file. You can set the `--file-mode` flag to control this. For example, to make the file readable and editable for your user, and readable to all system users, you would use:

```sh
monopass read Personal/Chase/receipt.pdf -o receipt.pdf --file-mode 0644
```

| Previous chapter | Next chapter |
| --- | --- |
| [Getting started](01-getting-started.md) | [Listing, moving, deleting, and versioning items](03-listing-moving-deleting-versioning.md) |
