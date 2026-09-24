# SQL Server 2016 CI fixture

This directory builds a disposable Windows Server 2019 Evaluation guest with
SQL Server 2016 SP3 Express patched to GDR build `13.0.6500.1`. It is intended
only for the project's legacy-source integration gate on an ephemeral Linux
runner with KVM. It is not a production deployment or a reusable VM image.

The workflow provides a strong, temporary password in
`DFE_MSSQL_2016_SA_PASSWORD` and calls:

```sh
bash tests/fixtures/mssql-2016/ci/start.sh "$RUNNER_TEMP/dfe-sql2016"
```

The same password is used for the guest Administrator and SQL Server `sa`
accounts. The script keeps generated credentials and disks under that private
temporary directory, exposes only `127.0.0.1:51416`, and returns only after the
guest verifies the generated SQL login, reports the exact server version over COM1, and the forwarded TCP port
accepts a connection. The guest remains running for the caller's fixture setup
and tests. Cleanup is an unconditional workflow step:

```sh
bash tests/fixtures/mssql-2016/ci/stop.sh "$RUNNER_TEMP/dfe-sql2016"
```

`start.sh` requires `qemu-system-x86_64`, `qemu-img`, `xorriso`, `curl`,
`python3`, writable `/dev/kvm`, four CPUs, 7 GiB of available memory, and 28 GiB
of free space. It uses a 60 GiB sparse disk, 6 GiB RAM, four vCPUs, IDE storage,
an e1000 NIC, restricted QEMU user networking, no display, and a one-hour
provisioning deadline.

The pinned Windows ISO uses its normal optical-boot confirmation. After QEMU
starts, `start.sh` sends a space key through QMP during that bounded prompt;
`Autounattend.xml` is then discovered from the second, read-only provisioning
CD. No VNC or interactive console is opened.

## Pinned Microsoft media

| Media | Bytes | SHA-256 authority |
|---|---:|---|
| [Windows Server 2019 Evaluation](https://software-static.download.prss.microsoft.com/dbazure/988969d5-f34g-4e03-ac9d-1f9786c66749/17763.3650.221105-1748.rs5_release_svc_refresh_SERVER_EVAL_x64FRE_en-us.iso) | 5,652,088,832 | `b490bbddaafd2c9604feaf9fb90bf556a550b6485e9c21ddcf6e36239f321c19` (project-measured; Microsoft did not publish a hash on the evaluated download page) |
| [SQL Server 2016 SP3 Express](https://download.microsoft.com/download/f/9/8/f982347c-fee3-4b3e-a8dc-c95383aa3020/sql16_sp3_dlc/en-us/SQLEXPR_x64_ENU.exe) | 564,016,512 | `123f35eb622e56a45a6a0ad951760aaba0df8b908f30ed5d4aa0f93bc93fd448` (project-measured; the executable is also Microsoft Authenticode-signed) |
| [SQL Server 2016 GDR KB5102340](https://catalog.s.download.windowsupdate.com/d/msdownload/update/software/secu/2026/06/sqlserver2016-kb5102340-x64_35e5ef7a44a1851cd658c5aef3294559d67cb817.exe) | 536,162,048 | `e86109191b199a1347ad7ff62d2c785d1caa5538fedafdf096c87ed0e78e0201` (Microsoft-published) |

Windows Server Evaluation requires activation and expires. Microsoft support
for SQL Server 2016 ended in July 2026, and Express cannot subscribe to ESUs.
The QEMU/KVM topology is an isolated compatibility fixture and is not claimed
as a Microsoft-supported production virtualization configuration.
