# AppleTun

## Description

A utility for creating and connecting to a local VPN for ios devices allowing HTTP proxy without device supervision for all connections (not limited to Wi-Fi)

## Installation

```shell
python3 -m pip install -U AppleTun
```

## Requirements

[StrongSwan](https://github.com/strongswan/strongswan) installation is required.
Installation of StrongSwan can be done via `brew install strongswan`, any other package manager, or a manual build (incase special flags are required, exporting of session keys to files for example).

Python requirements are stated in `requirements.txt`.

## Usage

```none
Usage: appletun [OPTIONS] COMMAND [ARGS]...

Options:
  --help  Show this message and exit.

Commands:
  install-profile  Install AppleTun VPN profile (override if already exists)
  remove-profile   Remove AppleTun VPN profile
  start            Start AppleTun VPN
  stop             Stop AppleTun VPN
```

## Example

In this example, a VPN profile is installed with together with Proxyman certificate for use with the http proxy.
After the installation the service is started and a connection to the VPN is established.

```shell
➜  appletun git:(master) ✗ appletun install-profile -C proxyman-ca.pem
Profile installed, please accept installation on device
Please allow installed certificate under Settings > General > About > Certificate Trust Settings

➜  appletun git:(master) ✗ appletun start
installed profile: AppleTunVPN PSK ************ HTTP 192.168.1.2:9090
VPN Running
```

The generated `ipsec.conf` configuration would look as follows:

```conf
conn AppleTun
  left=0.0.0.0                  # Server listens on any IPv4 address
  leftid=AppleTun               # Identity presented by the server
  leftsubnet=0.0.0.0/0,::/0     # Server-side networks (IPv4 and IPv6)
  leftauth=psk                  # Server uses a pre-shared key

  right=%any                    # Accept any client IP
  rightid=%any                  # Accept any client identity
  rightdns=%config4,%config6    # Push DNS settings (IPv4, IPv6)
  rightsubnet=%dynamic          # Dynamically assign subnets to clients
  rightsourceip=133.33.37.0/24,fec3:1337::0/112   # IPv4/IPv6 pool for clients
  rightauth=psk                 # Client also uses a pre-shared key

  ike=aes256-sha256-ecp256,aes256-sha256-modp2048!     # Phase 1 proposals
  esp=aes256-sha256-ecp256,aes256-sha256-modp2048!     # Phase 2 proposals
  keyexchange=ikev2             # Use IKEv2 protocol
  auto=add                      # Load connection at startup
```

While the following line would be added to `ipsec.secrets`:

```none
AppleTun : PSK "************"
```
