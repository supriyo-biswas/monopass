# Secure access to your vault

monopass asks you to approve the program that requests item access. This chapter shows how that approval is reused, how to revoke it, and how to change your master password.

## Know what you are approving

By default, an approval applies to the requesting command and its process tree. A request from, say `Gnome Terminal → bash → monopass`, is distinct from a request from `Konsole → bash → monopass` or `Gnome Terminal → zsh → monopass`. On the GUI variants, you can see the requesting application as in the example below. Always be sure to check that you're approving access to the right application.

![Unlock prompt](../../images/unlock.png)

Successful item approval lasts 15 minutes by default for that process tree. If you make a request via a different running instance of Gnome Terminal, but otherwise access it in the same way (such as `Gnome Terminal → bash → monopass`, to continue with our previous example), this access will be allowed as long as it is within that 15 minute approval duration.

The Linux CLI variant also remembers process trees, but it does not show them in the inline `Enter master password:` prompt.

To change the approval duration, update the `agent.authTtlSeconds` setting, for example to increase this period to 1 hour, you would use:

```sh
monopass write-setting agent.authTtlSeconds 3600
```

## Locking the database

monopass runs as an agent and must keep the encrypted database unlocked for the approval duration mentioned above. To revoke authorization and unload the encrypted database, use the `monopass lock` command.

The cached authorization for process trees is cleared immediately and all further requests to access items cause the password prompt to be displayed.

The actual database unload happens asynchronously; if ~60 seconds have passed since the lock request, and there are no in-flight requests from other processes, monopass unloads the database.

## Process authorization model

monopass supports a few different process authorization models:

* `process-chain`: The default process tree authorization described above. It remembers process trees such as `Gnome Terminal → bash → monopass` and once authenticated, it allows all access from the same process tree for the configured approval duration, even if the process ID (PID) changes because you opened another terminal window or another instance of the same application.
* `originating-process`: Once authenticated, allows all monopass access occurring from the same originating PID, such as accesses within the same terminal window or from the same instance of the application process for the configured approval duration. Different terminal windows or different instances of the same application will require re-entering your password again. **This weakens the security model** (see below for more details).
* `insecure-all`: Once authenticated, allows all monopass access from any process until the approval duration is over. **This is highly unsafe and strongly discouraged. It has no legitimate use.**.

`process-chain` is a good default, although in some cases it may be too restrictive. For example, imagine that you have bash, Python and Node scripts as part of your application. Even though you may be launching these scripts from the same terminal, the process trees would be different, you will end up receiving multiple prompts, which may be quite frustrating.

In this case, you may switch to the `originating-process` model, which would allow all access from the same terminal, like so:

```bash
monopass write-setting agent.processIdentificationType originating-process
```

> [!WARNING]
> Enabling `originating-process` can have surprising security implications.
> As an example, consider you ran a bash script in a terminal window that unlocked monopass, like so:
> ```
> $ bash ./deploy.sh
> [monopass] Enter master password:
> ...
> ```
>
> Immediately after, you installed a npm package from the same terminal. Unbeknownst to you, it contains a malicious post-install hook which tries to access monopass and steal your credentials:
> ```
> $ npm install evil-js
> ```
>
> The package would be able to successfully steal your password, since it was executed from the same originating process.
>
> This problem is even worse in the `insecure-all` mode, which would allow any process to access monopass once you've unlocked it anywhere.

To switch it back to the default, use:

```bash
monopass write-setting agent.processIdentificationType process-chain
```

## Change the master password

Changing the master password needs exclusive access to the encrypted database. First stop the local agent using:

* **Linux:** `systemctl --user stop monopass-agent.socket monopass-agent.service`
* **macOS:** `launchctl bootout gui/$(id -u)/com.monopass.agent`

Then, run:

```
monopass passwd
```

Enter your old master password and new password to set the new password. Once that is done, restart the agent again with:

* **Linux:** `systemctl --user start monopass-agent.socket monopass-agent.service`
* **macOS:** `launchctl bootstrap gui/$(id -u) ~/Library/LaunchAgents/com.monopass.agent.plist`

| Previous chapter | Next chapter |
| --- | --- |
| [Listing, moving, deleting, and versioning items](03-listing-moving-deleting-versioning.md) | [Sharing items](05-sharing-items.md) |
