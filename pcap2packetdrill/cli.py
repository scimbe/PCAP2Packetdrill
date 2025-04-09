#!/usr/bin/env python3
"""
Command Line Interface for PCAP2Packetdrill.

This module provides the command-line interface for the PCAP2Packetdrill tool.
"""

import os
import sys
from typing import List, Optional

import click

from pcap2packetdrill import __version__
from pcap2packetdrill.converter import PcapConverter
from pcap2packetdrill.protocols import SUPPORTED_PROTOCOLS


@click.command()
@click.version_option(version=__version__)
@click.argument("pcap_file", type=click.Path(exists=True))
@click.option(
    "-o",
    "--output",
    default=None,
    help="Output file for the generated packetdrill script",
)
@click.option(
    "-p",
    "--protocol",
    type=click.Choice(list(SUPPORTED_PROTOCOLS.keys()), case_sensitive=False),
    help="Protocol to filter (default: auto-detect)",
)
@click.option(
    "--client-ip",
    help="Client IP address to filter (default: auto-detect)",
)
@click.option(
    "--server-ip",
    help="Server IP address to filter (default: auto-detect)",
)
@click.option(
    "--client-port",
    type=int,
    help="Client port to filter (default: auto-detect)",
)
@click.option(
    "--server-port",
    type=int,
    help="Server port to filter (default: auto-detect)",
)
@click.option(
    "--relative-time/--absolute-time",
    default=True,
    help="Use relative timestamps (default: True)",
)
@click.option(
    "--template",
    help="Custom Jinja2 template file for output formatting",
)
@click.option(
    "--debug/--no-debug",
    default=False,
    help="Enable debug output",
)
def main(
    pcap_file: str,
    output: Optional[str],
    protocol: Optional[str],
    client_ip: Optional[str],
    server_ip: Optional[str],
    client_port: Optional[int],
    server_port: Optional[int],
    relative_time: bool,
    template: Optional[str],
    debug: bool,
) -> int:
    """
    Convert a PCAP file to a Packetdrill test script.

    PCAP_FILE: Path to the input PCAP file
    """
    try:
        if debug:
            click.echo(f"Processing {pcap_file}...")

        # Determine output file name if not specified
        if output is None:
            base_name = os.path.splitext(os.path.basename(pcap_file))[0]
            output = f"{base_name}.pkt"

        # Create converter instance
        converter = PcapConverter(
            pcap_file=pcap_file,
            protocol=protocol,
            client_ip=client_ip,
            server_ip=server_ip,
            client_port=client_port,
            server_port=server_port,
            relative_time=relative_time,
            template_file=template,
            debug=debug,
        )

        # Convert PCAP to packetdrill
        script = converter.convert()

        # Write to output file or stdout
        if output == "-":
            click.echo(script)
        else:
            with open(output, "w") as f:
                f.write(script)
            click.echo(f"Generated packetdrill script: {output}")

        return 0

    except Exception as e:
        click.echo(f"Error: {e}", err=True)
        if debug:
            import traceback
            traceback.print_exc()
        return 1


if __name__ == "__main__":
    sys.exit(main())
