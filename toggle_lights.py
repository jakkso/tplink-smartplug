#!/usr/bin/env python3
"""Create CLI for ``tp_link`` functionality."""

import click

from tplink_smartplug import send_command, COMMANDS


DEVICES = {"one": "192.168.1.79", "two": "192.168.1.70"}


@click.command()
@click.argument("state")
@click.option(
    "--device",
    default="one",
    help="Which device to trigger.  Defaults to device one. "
    "Valid states are `on` and `off`.",
)
def toggle(device, state):
    """Toggle device's relay to desired state.


    Device: Device name, valid names are `one` and `two`.

    State: Valid states are `on` and `off`.
    """
    if device not in DEVICES:
        return click.echo(f"Invalid device `{device}`")
    if state not in ("on", "off"):
        return click.echo(
            f"Invalid state `{state}`: `on` and `off` are the only valid values."
        )
    result = send_command(ip_address=DEVICES[device], command=COMMANDS[state])
    return click.echo(result)


if __name__ == "__main__":
    toggle()
