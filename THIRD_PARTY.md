# Third-party components

Versions and integrity hashes are pinned in `go.mod`, `go.sum` and `apps/desktop/package-lock.json`.

- Xray-core: Mozilla Public License 2.0; upstream https://github.com/XTLS/Xray-core.
- sing-tun / sing: GPL 3.0; upstream https://github.com/SagerNet/sing-tun and https://github.com/SagerNet/sing.
- gVisor: Apache 2.0; upstream https://gvisor.dev/.
- Wintun: upstream license shipped by the sing-tun distribution; https://www.wintun.net/.
- tailscale/wf: BSD 3-clause; https://github.com/tailscale/wf.
- bbolt: MIT; https://github.com/etcd-io/bbolt.
- Electron: MIT and bundled Chromium/Node third-party notices; these are retained in packaged applications.
- Go x/*: BSD 3-clause; https://go.dev/.
- miekg/dns: BSD 3-clause; https://github.com/miekg/dns.

Distributions that combine GPL components must preserve the applicable licenses and make the corresponding source available to their recipients. The repository contains the application source and build scripts; dependency source is identified by exact versions and Go checksums. See the upstream LICENSE/NOTICE files for authoritative terms.
