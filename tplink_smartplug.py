#!/usr/bin/env python3
#
# TP-Link Wi-Fi Smart Plug Protocol Client
# For use with TP-Link HS-100 or HS-110
#
# by Lubomir Stroetmann
# Copyright 2016 softScheck GmbH
#
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
#      http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
# See the License for the specific language governing permissions and
# limitations under the License.
#

import argparse
import socket

__version__ = 0.3

PORT = 9999

# Predefined Smart Plug Commands
# For a full list of commands, consult tplink_commands.txt
COMMANDS = {
    "info": '{"system":{"get_sysinfo":{}}}',
    "on": '{"system":{"set_relay_state":{"state":1}}}',
    "off": '{"system":{"set_relay_state":{"state":0}}}',
    "cloudinfo": '{"cnCloud":{"get_info":{}}}',
    "wlanscan": '{"netif":{"get_scaninfo":{"refresh":0}}}',
    "time": '{"time":{"get_time":{}}}',
    "schedule": '{"schedule":{"get_rules":{}}}',
    "countdown": '{"count_down":{"get_rules":{}}}',
    "antitheft": '{"anti_theft":{"get_rules":{}}}',
    "reboot": '{"system":{"reboot":{"delay":1}}}',
    "factoryreset": '{"system":{"reset":{"delay":1}}}',
    "energy": '{"emeter":{"get_realtime":{}}}',
    "resetschedule": '{"schedule":{"delete_all_rules":null,"erase_runtime_stat":null}}',
    "ledoff": '{"system":{"set_led_off":{"off":1}}}',
    "ledon": '{"system":{"set_led_off":{"off":0}}}',
}


def encrypt(string: str) -> bytearray:
    """Encrypt string into TP-Link Smart Home Protocol format.

    XOR Autokey Cipher with starting key = 171

    :param string: str
    :return: bytearray of encrypted string.
    """
    string = bytes(string, encoding="utf8")
    key = 171
    message = bytearray((0, 0, 0, 0))  # Setup initial state, as per v0.1
    for char in string:
        encrypted_char = key ^ char  # XOR key with int representing each character
        message.append(encrypted_char)
        key = encrypted_char  # Update key to previous encrypted character.
    return message


def decrypt(string: bytes) -> str:
    """Decrypt TP-Link Smart Home Protocol messages.

    XOR Autokey Cipher with starting key = 171
    :param string: bytes
    :return: str decrypted message from device.
    """

    key = 171
    result = ""
    for char in string:
        result += chr(key ^ char)
        key = char
    return result


def send_command(ip_address: str, command: str) -> str:
    """Send ``command`` to device located at ``ip_address``.

    :param ip_address: string
    :param command: string
    :return: string, decrypted message from device.
    """
    try:
        sock_tcp = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        sock_tcp.connect((ip_address, PORT))
        sock_tcp.send(encrypt(command))
        data = sock_tcp.recv(2048)
        sock_tcp.close()
        return decrypt(data[4:])
    except socket.error:
        return f"Could not connect to host {ip_address }:{PORT}"


def main():
    """Create original, example CLI."""

    def validate_hostname(hostname):
        """Check if hostname is valid."""
        try:
            socket.gethostbyname(hostname)
        except socket.error:
            parser.error("Invalid hostname.")
        return hostname

    # Parse commandline arguments
    parser = argparse.ArgumentParser(description="TP-Link Wi-Fi Smart Plug Client v" + str(__version__))
    parser.add_argument("-t", "--target", metavar="<hostname>", required=True, help="Target hostname or IP address",
                        type=validate_hostname)
    group = parser.add_mutually_exclusive_group(required=True)
    group.add_argument("-c", "--command", metavar="<command>",
                       help="Preset command to send. Choices are: " + ", ".join(COMMANDS), choices=COMMANDS)
    group.add_argument("-j", "--json", metavar="<JSON string>", help="Full JSON string of command to send")
    args = parser.parse_args()

    # Set target IP, port and command to send
    ip = args.target
    port = 9999
    if args.command is None:
        cmd = args.json
    else:
        cmd = COMMANDS[args.command]

    # Send command and receive reply
    try:
        sock_tcp = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        sock_tcp.connect((ip, port))
        sock_tcp.send(encrypt(cmd))
        data = sock_tcp.recv(2048)
        sock_tcp.close()

        print("Sent:     ", cmd)
        print("Received: ", decrypt(data[4:]))
    except socket.error:
        quit("Could not connect to host " + ip + ":" + str(port))
