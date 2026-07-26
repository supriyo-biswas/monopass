# Use the local agent API

Some applications may want to seek a deeper level of integration than what is possible with the `monopass` command. In such cases, you may want to directly interact with the monopass agent Unix socket, which provides an HTTP API for querying directories, items, and files. In fact, the monopass CLI commands such as `mv`, `cp`, and `show` also consume the same API.

The example uses Python and HTTPX. HTTPX supports Unix-domain sockets through [`httpx.HTTPTransport(uds=...)`](https://www.python-httpx.org/advanced/transports/). Make sure to also refer to the [API reference](../references/api-reference.md).

You may like to review the code example directly, in which case you should skip to [set up the project](#set-up-the-project).

## Understanding the authorization process

To access items from monopass, you need to first authenticate with the agent. You do this by making a request to the `/api/v1/auth/unlock/methods` API, which provides you with a list of authentication methods. A typical request looks like this:

```
GET /api/v1/auth/unlock/methods HTTP/1.1

HTTP/1.1 200 OK

{
  "methods": [
    {
      "url": "/api/v1/auth/unlock/direct",
      "accepts_master_password": true
    }
  ]
}
```

Your client then makes a POST request to the first URL in the `methods` array. If `accepts_master_password` is set to `true`, you'll also send the `Authorization` header with a `Bearer` token set to the base64-encoded value of the password, like so:

```
POST /api/v1/auth/unlock/direct HTTP/1.1
Authorization: Bearer <base64 encoded password>
```

An HTTP 200 OK signifies that you're authenticated successfully. A 403 indicates that the user provided an incorrect password or, when `accepts_master_password` is set to `false`, dismissed the GUI prompt for your application's request to authenticate.

Once you've authenticated, the authorization is valid for 15 minutes by default for the process tree (such as `Terminal → bash → my_app`); whenever monopass receives a request, it automatically allows that request if it originates from an existing process tree that has authenticated in the past.

When you're performing multiple operations, the best way to handle this is to look for `403` errors with `{"error": {"code": "access_denied"}}` in the response, and repeat the authorization flow described above.

There are a few things to note, in addition to the above flow:

- The URLs advertised by the `/api/v1/auth/unlock/methods` API are subject to change, so do not hardcode them in your application. Instead, call the methods endpoint and then request the first returned URL.
- By default, the direct method where your application directly sends passwords to the agent is limited to the `monopass` CLI only. This prevents programs from unnecessarily asking for your password, which an untrusted program could use to steal your credentials. A monopass user must trust external programs explicitly before the direct method is available to them.
- In most variants (except for the Linux CLI variant), you don't need to trust the external program; let the monopass agent prompt the user for their password via the default method.
- When your application is running within an X or Wayland session, advertise the display session ID to monopass using the `X-Client-Capabilities` header with the value set to either `x-session=N` or `wayland-session=N`:

```
GET /api/v1/auth/unlock/methods HTTP/1.1
X-Client-Capabilities: x-session=:0
```

## Set up the project

We'll begin by creating a project directory and installing the `httpx` library. In this example, we've used the `~/monopass-integration` directory for our project.

```sh
mkdir ~/monopass-integration
cd ~/monopass-integration

python3 -m venv .venv
.venv/bin/pip install httpx
```

We'll run any further commands from the `~/monopass-integration` directory.

## The client wrapper

Save the following shared setup code as `main.py`, which implements `MonopassClient`, a client that wraps up the authorization logic that we reviewed above, and provides some convenience methods.

The client owns the Unix-socket connection and authorization retry, so every item API operation follows the same rule: it makes the requested call once, tries to unlock after receiving `403 access_denied`, then retries that request exactly once. Any other first response, an unlock failure, or any retry failure (including another `403`) raises an HTTPX exception.

You'll mostly use the `.get()`, `.post()`, `.put()`, `.patch()`, `.delete()`, and `.paginated_get()` methods. The first five are HTTP requests with their respective methods, and the `.paginated_get()` method makes it easier to work with listing API calls.

```python
#!/usr/bin/env python3

import base64
import getpass
import os
import sys
import httpx
from pathlib import Path


class MonopassClient:
    def __init__(self):
        transport = httpx.HTTPTransport(uds=self._socket_path())
        self._client = httpx.Client(
            transport=transport,
            base_url="http://localhost/api/v1",
            timeout=httpx.Timeout(180.0),
        )

    def __enter__(self):
        return self

    def __exit__(self, exc_type, exc_value, traceback):
        self._client.close()

    @staticmethod
    def _socket_path():
        runtime = os.environ.get("XDG_RUNTIME_DIR")
        if runtime:
            return str(Path(runtime) / "monopass" / "agent.sock")
        if sys.platform == "darwin":
            return str(
                Path.home()
                / "Library"
                / "Application Support"
                / "monopass"
                / "agent.sock"
            )
        raise RuntimeError("set XDG_RUNTIME_DIR for the agent socket")

    @staticmethod
    def _client_capabilities():
        if sys.platform != "linux":
            return {}
        if display := os.environ.get("DISPLAY"):
            return {"X-Client-Capabilities": f"x-session={display}"}
        if display := os.environ.get("WAYLAND_DISPLAY"):
            return {"X-Client-Capabilities": f"wayland-session={display}"}
        return {}

    def _request(self, method, *args, **kwargs):
        request = self._client.build_request(method, *args, **kwargs)
        return self.make_request(request)

    def get(self, *args, **kwargs):
        return self._request("GET", *args, **kwargs)

    def post(self, *args, **kwargs):
        return self._request("POST", *args, **kwargs)

    def put(self, *args, **kwargs):
        return self._request("PUT", *args, **kwargs)

    def patch(self, *args, **kwargs):
        return self._request("PATCH", *args, **kwargs)

    def delete(self, *args, **kwargs):
        return self._request("DELETE", *args, **kwargs)

    def paginated_get(self, *args, **kwargs):
        page_params = httpx.QueryParams(kwargs.pop("params", None))
        page_params = page_params.remove("marker").set("count", 200)
        while True:
            page = self.get(*args, params=page_params, **kwargs).json()
            yield from page["entries"]

            marker = page["next_marker"]
            if marker is None:
                return
            page_params = page_params.set("marker", marker)

    @staticmethod
    def _is_access_denied(response):
        return (
            response.status_code == 403
            and response.json()["error"]["code"] == "access_denied"
        )

    def _authorize(self):
        headers = self._client_capabilities()
        discovery = self._client.get("/auth/unlock/methods", headers=headers)
        discovery.raise_for_status()
        methods = discovery.json()["methods"]
        if len(methods) == 0:
            raise Exception(
                "no authorization methods available! "
                "did you add python3 as a trusted process?"
            )

        method = methods[0]
        if method["accepts_master_password"]:
            password = getpass.getpass("Enter master password: ")
            token = base64.b64encode(password.encode("utf-8")).decode("ascii")
            headers["Authorization"] = f"Bearer {token}"

        url = method["url"].removeprefix("/api/v1")
        self._client.post(url, headers=headers).raise_for_status()

    def make_request(self, r: httpx.Request) -> httpx.Response:
        response = self._client.send(r)
        if not self._is_access_denied(response):
            response.raise_for_status()
            return response

        self._authorize()
        response = self._client.send(r)
        response.raise_for_status()
        return response
```

## Testing out your first request

Add the following at the bottom of the `main.py` file. This code lists out all the directories stored:

```python
def main():
    with MonopassClient() as client:
        for dir in client.paginated_get("/dirs"):
            print(dir)


if __name__ == '__main__':
    main()
```

Then, run your code with:

```sh
.venv/bin/python main.py
```

On macOS and desktop Linux, you'll receive a GUI unlock prompt. Type in your password as usual to see the list of directories. The output may vary based on the directories that you have.

```
$ .venv/bin/python main.py
{'name': 'GitCredentials', 'created_at': '2026-07-26T12:43:54Z', 'updated_at': '2026-07-26T12:43:54Z', 'items': 1}
{'name': 'Personal', 'created_at': '2026-07-26T12:42:28Z', 'updated_at': '2026-07-26T12:42:28Z', 'items': 1}
```

In headless Linux environments, you may receive an exception like this:

```
$ .venv/bin/python main.py
Traceback (most recent call last):
  File "/home/supriyo/monopass-integration/main.py", line 127, in <module>
    main()
...
Exception: no authorization methods available! did you add python3 as a trusted process?
```

In this case, you'll need monopass to trust the Python process. Run the following command to add the Python process as a trusted program that can provide your master password directly:

```sh
monopass write-setting agent.trustedProgramPaths '["'$(readlink -f .venv/bin/python)'"]'
```

Then, try re-running `.venv/bin/python main.py` and enter your master password; you should see the list of directories as shown above.
