import plistlib
import re
import secrets
import string
from pathlib import Path
from sys import platform
from typing import Any, IO, Optional, Union

import click
import psutil
from plumbum import local
from plumbum.commands.base import BoundCommand
from plumbum.machines.local import LocalCommand
from pymobiledevice3.cli.cli_common import Command
from pymobiledevice3.lockdown import LockdownServiceProvider
from pymobiledevice3.services.mobile_config import MobileConfigService

BASE_VPN_CONFIG_FORMAT = """
conn {vpn_name}
  left=0.0.0.0                  # Server listens on any IPv4 address
  leftid={vpn_name}             # Identity presented by the server
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
"""

PROFILE_UUID = 'B6CFC043-A872-4EE1-BADF-53471B910BA7'

ipsec: Union[LocalCommand, BoundCommand] = local['sudo']['ipsec']


def get_machine_ips(ipv4: bool = True,
                    ipv6: bool = True) -> list[str]:
    """ Retrieve all ip addresses belonging to the current machine (excluding loopback) """
    ifaces: dict[str, Any] = psutil.net_if_stats()
    addresses: list[str] = []
    for iface, addrs in psutil.net_if_addrs().items():
        if 'loopback' in ifaces[iface].flags:
            continue
        for addr in addrs:
            if ipv4 and addr.family.name == 'AF_INET':  # IPv4
                addresses.append(addr.address)
            elif ipv6 and addr.family.name == 'AF_INET6':  # IPv6
                addresses.append(addr.address)

    return addresses


def get_vpn_config() -> Path:
    """ Locate VPN config dir """
    if 'darwin' == platform:
        return Path(local['brew']('--prefix').strip()) / 'etc'
    else:
        return Path('/etc')


def check_vpn_config_exist(config: Path,
                           vpn_name: str) -> bool:
    """ Check if the vpn config already exists in ipsec.conf """
    ipsec_conf_file: Path = config / 'ipsec.conf'
    if ipsec_conf_file.exists():
        ipsec_conf: str = ipsec_conf_file.read_text()
        return f'conn {vpn_name}\n' in ipsec_conf

    return False


def write_new_vpn_config(config: Path,
                         vpn_name: str) -> None:
    """ Create a new config for a VPN and write it to ipsec.config if no config with the same name exists """
    ipsec_conf_file: Path = config / 'ipsec.conf'
    if not check_vpn_config_exist(config, vpn_name):
        raw_config = BASE_VPN_CONFIG_FORMAT.format(vpn_name=vpn_name)
        with ipsec_conf_file.open('a') as f:
            f.write(raw_config)


def get_vpn_secret(config: Path,
                   server_id: str) -> list[str]:
    """ Retrieve any existing secrets for a given server_id from ipsec.secrets"""
    secrets_file: Path = config / 'ipsec.secrets'
    if secrets_file.exists():
        return re.findall(f'{server_id}.*?:.*?PSK.*?"(.*)"', secrets_file.read_text())

    return []


def write_vpn_secret(config: Path,
                     server_id: str,
                     psk: str) -> None:
    """ Write a new PSK secret to ipsec.secrets if not already exists"""
    if psk not in get_vpn_secret(config, server_id):
        secrets_file: Path = config / 'ipsec.secrets'
        with secrets_file.open('a') as f:
            f.write(f'\n{server_id} : PSK "{psk}"')


def generate_profile(server_address: str,
                     vpn_name: str,
                     psk: str,
                     http_proxy_port: int = 9090,
                     http_proxy_addr: Optional[str] = None,
                     http_proxy_cert: Optional[bytes] = None) -> dict[str, Any]:
    """ Generate a profile to be installed on an iOS device for the given VPN """
    http_proxy_addr = server_address if http_proxy_addr is None else http_proxy_addr
    profile: dict[str, Any] = {
        'PayloadDisplayName': f'{vpn_name}VPN PSK {psk} HTTP {http_proxy_addr}:{http_proxy_port}',
        'PayloadIdentifier': PROFILE_UUID,
        'PayloadRemovalDisallowed': False,
        'PayloadType': 'Configuration',
        'PayloadUUID': PROFILE_UUID,
        'PayloadVersion': 1,
        'PayloadContent': [{'IKEv2': {'AuthenticationMethod': 'SharedSecret',
                                      'ChildSecurityAssociationParameters': {'DiffieHellmanGroup': 14,
                                                                             'EncryptionAlgorithm': 'AES-256',
                                                                             'IntegrityAlgorithm': 'SHA2-256'},
                                      'DeadPeerDetectionRate': 'Medium',
                                      'DisableMOBIKE': 0,
                                      'DisableRedirect': 0,
                                      'EnableCertificateRevocationCheck': 0,
                                      'EnableFallback': 0,
                                      'EnablePFS': 0,
                                      'IKESecurityAssociationParameters': {'DiffieHellmanGroup': 14,
                                                                           'EncryptionAlgorithm': 'AES-256',
                                                                           'IntegrityAlgorithm': 'SHA2-256'},
                                      'RemoteAddress': server_address,
                                      'RemoteIdentifier': vpn_name,
                                      'SharedSecret': psk,
                                      'UseConfigurationAttributeInternalIPSubnet': False},
                            'PayloadDescription': 'Configures VPN settings',
                            'PayloadDisplayName': 'VPN',
                            'PayloadIdentifier': f'com.apple.vpn.managed.{PROFILE_UUID}',
                            'PayloadType': 'com.apple.vpn.managed',
                            'PayloadUUID': PROFILE_UUID,
                            'PayloadVersion': 1,
                            'Proxies': {'HTTPEnable': True,
                                        'HTTPPort': http_proxy_port,
                                        'HTTPProxy': http_proxy_addr,
                                        'HTTPSEnable': True,
                                        'HTTPSPort': http_proxy_port,
                                        'HTTPSProxy': http_proxy_addr},
                            'UserDefinedName': vpn_name,
                            'VPNType': 'IKEv2'}],
    }
    if http_proxy_cert is not None:
        profile['PayloadContent'].append(
            {'PayloadIdentifier': 'com.apple.security.root.86FD9307-9CAC-4401-ABD4-FE0F70521A62',
             'PayloadType': 'com.apple.security.root',
             'PayloadUUID': '86FD9307-9CAC-4401-ABD4-FE0F70521A62',
             'PayloadVersion': 1,
             'PayloadContent': http_proxy_cert})
    return profile


def generate_and_install_profile(service: MobileConfigService,
                                 server_address: Optional[str] = None,
                                 vpn_name: str = 'AppleTun',
                                 psk: Optional[str] = None,
                                 http_proxy_port: int = 9090,
                                 http_proxy_addr: Optional[str] = None,
                                 http_proxy_cert: Optional[bytes] = None,
                                 no_write_config: bool = True) -> None:
    """ Generate and install a VPN profile """
    config: Path = get_vpn_config()
    if psk is None:
        vpn_secrets = get_vpn_secret(config, vpn_name)
        if len(vpn_secrets) == 0:
            characters = string.ascii_letters + string.digits
            psk = ''.join(secrets.choice(characters) for _ in range(12))
        else:
            psk = vpn_secrets[0]
    server_address = server_address if server_address is not None else get_machine_ips(ipv4=True, ipv6=False)[0]
    http_proxy_addr = http_proxy_addr if http_proxy_addr is not None else server_address

    profile = generate_profile(server_address, vpn_name, psk, http_proxy_port, http_proxy_addr, http_proxy_cert)
    service.install_profile(plistlib.dumps(profile))

    if not no_write_config:
        write_new_vpn_config(config, vpn_name)
        write_vpn_secret(config, vpn_name, psk)


@click.group()
def cli():
    pass


@cli.command(cls=Command)
def start(service_provider: LockdownServiceProvider) -> None:
    """ Start AppleTun VPN """
    service = MobileConfigService(lockdown=service_provider)
    profiles = service.get_profile_list()
    if PROFILE_UUID in profiles['ProfileManifest'].keys():
        description = profiles['ProfileManifest'][PROFILE_UUID]['Description']
        print(f'Installed profile: {description}')
    else:
        print('Warning: generated AppleTun profile not found')

    ipsec('restart')
    print('VPN Running')
    print('Please activate VPN connection on Client device')


@cli.command()
def stop() -> None:
    """ Stop AppleTun VPN """
    ipsec('stop')


@cli.command(cls=Command)
@click.option('-s', '--server-address',
              show_default='First non-loopback ipv4 address assigned to this machine',
              help='Address of the server for the client to connect to')
@click.option('-n', '--vpn-name', default="AppleTun", show_default=True, help='Name to assign the VPN')
@click.option('-p', '--psk',
              show_default='If one already exist for the same vpn name, use it, otherwise generated random PSK',
              help='PSK for the authentication with the VPN')
@click.option('-H', '--http_proxy-addr', show_default="Same as server address",
              help='Address of http proxy')
@click.option('-P', '--http-proxy-port', type=click.IntRange(0x0000, 0xffff), default=9090,
              show_default=True, help='Port for http proxy')
@click.option('-C', '--http_proxy-cert', type=click.File('rb'), default=None,
              show_default="No certificate would be installed",
              help='Certificate for the http proxy to install with the profile')
@click.option('--no-write-config', is_flag=True,
              help='Disable writing of the VPN configuration to ipsec.config/ipsec.secrets')
def install_profile(service_provider: LockdownServiceProvider,
                    server_address: Optional[str],
                    vpn_name: str,
                    psk: Optional[str],
                    http_proxy_port: int,
                    http_proxy_addr: Optional[str],
                    http_proxy_cert: Optional[IO],
                    no_write_config: bool) -> None:
    """ Install AppleTun VPN profile (override if already exists) """
    service = MobileConfigService(lockdown=service_provider)
    service.remove_profile(PROFILE_UUID)
    raw_cert = None
    if http_proxy_cert is not None:
        raw_cert = http_proxy_cert.read()
    generate_and_install_profile(service, server_address, vpn_name, psk, http_proxy_port, http_proxy_addr, raw_cert,
                                 no_write_config)
    print('Profile installed, please accept installation on device')
    if http_proxy_cert is not None:
        print('Please allow installed certificate under Settings > General > About > Certificate Trust Settings')


@cli.command(cls=Command)
def remove_profile(service_provider: LockdownServiceProvider) -> None:
    """ Remove AppleTun VPN profile """
    service = MobileConfigService(lockdown=service_provider)
    service.remove_profile(PROFILE_UUID)


if __name__ == '__main__':
    cli()
