---
icon: material/new-box
---

!!! question "Since sing-box 1.14.0"

### Structure

```json
{
  "type": "snell",
  "tag": "snell-out",

  "server": "127.0.0.1",
  "server_port": 1080,
  "version": 4,
  "psk": "password",
  "userkey": "",
  "reuse": false,
  "network": "tcp",
  "obfs_mode": "",
  "obfs_host": "",

  ... // Dial Fields
}
```

### Version 6 Structure

```json
{
  "type": "snell",
  "tag": "snell-out",

  "server": "127.0.0.1",
  "server_port": 1080,
  "version": 6,
  "psk": "password",
  "userkey": "",
  "reuse": false,
  "network": "tcp",
  "mode": "",

  ... // Dial Fields
}
```

### Fields

#### server

==Required==

The server address.

#### server_port

==Required==

The server port.

#### version

==Required==

The Snell protocol version, one of `2` `3` `4` `6`.

Version `2` supports TCP only and always enables connection reuse. Version `3`
supports TCP and UDP over TCP, without connection reuse. Versions `2` and `3`
do not support `userkey`.

Version `4` supports HTTP obfuscation (`obfs_mode` / `obfs_host`); version `6`
replaces it with traffic shaping (`mode`) and requires a `psk` of 12 to 255
bytes.

!!! note

    Since we intentionally do not support the QUIC proxy mode of Snell v5, the v5 wire protocol
    is effectively identical to v4, so no separate v4 server or v5 client is provided.

#### psk

==Required==

The pre-shared key.

#### userkey

The user key, used to authenticate against a multi-user server.

#### reuse

Enable connection reuse (the Snell v2 `CONNECT` command). Always enabled for
version `2`; unsupported for version `3`.

#### network

Enabled network

One of `tcp` `udp`.

Version `2` defaults to and only supports `tcp`; explicitly enabling `udp` is an
error. Both networks are enabled by default for other versions.

#### obfs_mode

==Versions 2, 3 and 4 only==

Obfuscation mode, one of `none` `http` `tls`.

`none` is used by default.

#### obfs_host

==Versions 2, 3 and 4 only==

The HTTP `Host` header when `obfs_mode` is `http`, or the server name when it is
`tls`. Defaults to `bing.com` for HTTP and `cloudfront.net` for TLS.

#### mode

==Version 6 only==

Traffic shaping mode, one of `default` `unshaped` `unsafe-raw`.

`default` is used by default.

### Dial Fields

See [Dial Fields](/configuration/shared/dial/) for details.
