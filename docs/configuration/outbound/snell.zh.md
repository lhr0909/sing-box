---
icon: material/new-box
---

!!! question "自 sing-box 1.14.0 起"

### 结构

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

  ... // 拨号字段
}
```

### 版本 6 结构

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

  ... // 拨号字段
}
```

### 字段

#### server

==必填==

服务器地址。

#### server_port

==必填==

服务器端口。

#### version

==必填==

Snell 协议版本，`2` `3` `4` `6` 之一。

版本 `2` 仅支持 TCP，并自动启用连接复用。版本 `3` 支持 TCP 和通过 TCP 传输的 UDP，
不支持连接复用。版本 `2` 和 `3` 不支持 `userkey`。

版本 `4` 支持 HTTP 混淆（`obfs_mode` / `obfs_host`）；版本 `6` 以流量整形（`mode`）
取而代之，并要求 `psk` 长度为 12 到 255 字节。

!!! note

    由于我们有意不支持 Snell v5 的 QUIC 代理模式，v5 的线路协议实际上与 v4 没有区别，
    因此不提供独立的 v4 服务器和 v5 客户端。

#### psk

==必填==

预共享密钥。

#### userkey

用户密钥，用于向多用户服务器进行认证。

#### reuse

启用连接复用（Snell v2 `CONNECT` 命令）。版本 `2` 始终启用；版本 `3` 不支持此选项。

#### network

启用的网络协议。

`tcp` 或 `udp`。

版本 `2` 默认且仅支持 `tcp`；其他版本默认全部启用。显式为版本 `2` 启用 `udp` 会报错。

#### obfs_mode

==仅版本 2、3、4==

混淆模式，`none` `http` `tls` 之一。

默认为 `none`。

#### obfs_host

==仅版本 2、3、4==

`obfs_mode` 为 `http` 时发送的 HTTP `Host` 头，或为 `tls` 时发送的服务器名称。

HTTP 默认为 `bing.com`，TLS 默认为 `cloudfront.net`。

#### mode

==仅版本 6==

流量整形模式，`default` `unshaped` `unsafe-raw` 之一。

默认为 `default`。

### 拨号字段

参阅 [拨号字段](/zh/configuration/shared/dial/)。
