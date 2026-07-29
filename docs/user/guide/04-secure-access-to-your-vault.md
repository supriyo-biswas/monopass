# Secure access to your vault

monopass asks you to approve the program that requests item access. This chapter shows how that approval is reused, how to revoke it, and how to change your master password.

## Know what you are approving

An approval applies to the requesting command and its process tree. A request from `Terminal → bash → monopass`, for example, is distinct from a command launched in another terminal or by another application. On the GUI variants, you can see the requesting application as in the example below. Always be sure to check that you're approving access to the right application.

![Unlock prompt](../../images/unlock.png)

Successful item approval lasts 15 minutes by default for that process tree.

The Linux CLI variant also remembers process trees, but it does not show them in the inline `Enter master password:` prompt.

## Locking the database

monopass runs as an agent and must keep the encrypted database unlocked for the 15-minute duration mentioned above. To force all requests to require authorization and unload the encrypted database, use the `monopass lock` command.

The cached authorization for process trees is cleared immediately and all further requests to access directories or items cause the password prompt to be displayed.

The actual database unload happens asynchronously; if ~60 seconds have passed since the lock request, and there are no in-flight requests from other processes, monopass unloads the database.

## Change the master password

Changing the master password needs exclusive access to the encrypted database. First stop the local agent using:

* **Linux:** `systemctl --user stop monopass-agent.socket monopass-agent.service`
* **macOS:** `launchctl bootout gui/$(id -u)/com.monopass.agent`
* **Windows PowerShell:** `Get-Process monopass | Stop-Process`

Then, run:

```
monopass passwd
```

Enter your old master password and new password to set the new password. Once that is done, restart the agent again with:

* **Linux:** `systemctl --user start monopass-agent.socket monopass-agent.service`
* **macOS:** `launchctl kickstart -k gui/$(id -u)/com.monopass.agent`
* **Windows:** run any monopass client command; it starts the verified per-user
  named-pipe agent on demand.

| Previous chapter | Next chapter |
| --- | --- |
| [Listing, moving, deleting, and versioning items](03-listing-moving-deleting-versioning.md) | [Sharing items](05-sharing-items.md) |
