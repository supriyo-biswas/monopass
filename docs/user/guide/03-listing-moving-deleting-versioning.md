
# Listing, moving, deleting and versioning items

You've been saving items in monopass, and your items have been growing. We'll see how to manage your items in this chapter.

## Using globs in `ls`

Imagine that your `Personal` directory has a lot of items; for example:

```
$ monopass ls Personal
Apple
Airbnb
Amazon
Facebook
GitHub
Google
Grubhub
IMDB
Uber
```

To see a subset of these items, you can use glob patterns like so. Since these globs can potentially conflict with those of the shell, globs must always be wrapped in single or double quotes, like so:

```sh
monopass ls 'Personal/G*'
```

This will produce the following items from the above list:

```
GitHub
Google
Grubhub
```

The full range of glob-like expressions are supported. For example, to list items that begin with `G` but are not followed by the letter `r`, you could use:

```sh
monopass ls 'Personal/G[^r]*'
```

This will result in the following items being displayed, excluding `Grubhub` from our above example:

```
$ monopass ls 'Personal/G[^r]*'
GitHub
Google
```

## Moving and renaming items

You can move items between directories, using the `monopass mv` command. For example, to move the item called `AWS Access Key` from the `Personal` directory to the Work directory, use:

```sh
monopass mv "Personal/AWS Access Key" Work
```

You can also use glob expressions, for example, to move all the items starting with `G` in the `Personal` directory to `Work`, you would use:

```sh
monopass mv 'Personal/G*' Work
```

You can also rename items using the `mv` command, for example, to rename the item called `AWS Access Key` to `My AWS Credentials`, use:

```sh
monopass mv "Personal/AWS Access Key" "Personal/My AWS Credentials"
```

## Deleting an item

Once you no longer need an item, use `monopass rm` to delete it, which by default moves it to a hidden `Trash` directory.

For example, to delete the item `Airbnb` from the `Personal` directory, use:

```sh
monopass rm Personal/Airbnb
```

You can confirm that the item was moved to trash by listing the `Trash` directory using `monopass ls Trash`. Trashed items are removed 180 days after they are moved.

If you want to remove the item immediately, use `monopass rm -f Personal/Airbnb`.

You can delete an entire directory along with its items using the `-r` flag. For example, to delete the entire `Work` directory along with its items, use:

```sh
monopass rm -r Work
```

## Recover an item from Trash

If you happen to delete an item and want it back later, begin by listing the `Trash` folder, and restore the item you want out of the trash:

```
$ monopass ls 'Trash/GitHub*'
GitHub
$ monopass mv Trash/GitHub Personal/GitHub
```

However, if you used `-f` to delete the item, there's no way to recover it.

## Versioning and undoing changes

Whenever you edit items with `monopass edit`, behind the scenes, monopass keeps around the old versions for 30 days. This allows you to restore old versions.

Imagine that you end up regenerating your password for the `Personal/GitHub` item, but forgot to actually change your password on the website. Now, the password saved no longer works, so you would first begin by listing all the old versions using `monopass ls-versions`:

```
monopass ls-versions Personal/GitHub
```

This shows you all the previous versions of an item:

```
$ monopass ls-versions Personal/GitHub
4	2026-07-25T09:47:10Z
3	2026-07-25T09:31:52Z
2	2026-07-25T09:24:06Z
1	2026-07-25T09:18:41Z
```

Let's say you want to undo your last changes, so you'd want to restore version 3. Use `monopass restore` with the item and version number like so:

```sh
monopass restore Personal/GitHub 3
```

This will create a new version with the data stored in version 3, as you can confirm using the `monopass show` command. Note that the version number has increased to 5:

```
$ monopass restore Personal/GitHub 3
# no output: version 5 now contains version 3's data
$ monopass show Personal/GitHub
Name: GitHub
Created: 2026-07-25T09:18:41Z
Updated: 2026-07-25T09:49:03Z
Versions: 5
Fields:
  password: ******
  totp: ******
  username: your.name
```

| Previous chapter | Next chapter |
| --- | --- |
| [Creating directories and items](02-creating-dirs-and-items.md) | [Securing access to your vault](04-secure-access-to-your-vault.md) |
