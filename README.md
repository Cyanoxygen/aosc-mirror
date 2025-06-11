aosc-mirror
-----------

A simple program suite to set up real-time mirror for the AOSC OS APT repository.

> [!Warning]
> This project is currently **work in progress**. Basic functionality is implemented, but there are still lots of things to implement.

> [!Warning]
> This project will be rebased and transferred to [AOSC-Dev](https://github.com/AOSC-Dev) organization upon completion.

This suite comes with two parts:

- `sync-client`: Runs on the downstream mirror server. It runs in the background, listens to sync requests coming from the upstream mirror.
- `sync-invoker`: Runs on the origin server. It runs once the APT metadata gets updated.

Usage
-----

Origin server
=============

To make downstream mirrors accept your sync request, you must generate a pair of Ed25519 key pair first:

```bash
sync-invoker genkey > privkey
cat privkey | sync-invoker pubkey | tee pubkey
```

And distribute the public key to the downstream mirrors. Let downstream mirrors configure the `sync-client`, and in return, gather the `sync-client` endpoint URLs they provide to you.

> [!Tip]
>
> The `sync-client` currently lacks rate limiting functionality. For enhanced security and control it is **highly recommended** to set up a private network between you and the downstream mirrors.

Store the endpoint one by one to a file:

```bash
cat endpoints.txt
http://172.21.123.101:1234/do-sync
http://172.21.123.102:1234/do-sync
http://172.21.123.103:1234/do-sync
http://172.21.123.104:1234/do-sync
http://172.21.123.105:1234/do-sync
http://172.21.123.106:1234/do-sync
```

Finally, integrate `sync-invoker` to the script or routine that updates the APT metadata:

```bash
p-vector ...
# APT metadata updated
sync-invoker invoke -p privkey.txt -r /path/to/report/directory -t `date '+%s'` -e endpoints.txt
```

Downstream mirrors
==================

1. Ask the upstream mirror for a public key. You need the public key to verify the sync request.
2. Connect your mirror to the private network (if the upstream requested), or expose the endpoint to your web server.
3. Determine which address and port to be allocated for the sync client.
4. Write a configuration file (refer to `config.example.toml` for details), then start the sync client:

```bash
RUST_LOG=info ./target/debug/sync-client -c ./config.aosc.example.toml daemon
```

`sync-client` will listen to all addresses and ports you configured.
