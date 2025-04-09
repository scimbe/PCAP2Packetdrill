#!/usr/bin/env python3
"""
Command Line Interface for PCAP2Packetdrill.

This module provides the command-line interface for the PCAP2Packetdrill tool.
"""

import os
import sys
from typing import List, Optional, Dict

import click

from pcap2packetdrill import __version__
from pcap2packetdrill.converter import PcapConverter
from pcap2packetdrill.replay_generator import ReplayTestGenerator
from pcap2packetdrill.protocols import SUPPORTED_PROTOCOLS


@click.group()
@click.version_option(version=__version__)
def cli():
    """PCAP2Packetdrill - Convert PCAP files to Packetdrill test scripts."""
    pass


@cli.command(name="convert")
@click.argument("pcap_file", type=click.Path(exists=True))
@click.option(
    "-o",
    "--output",
    default=None,
    help="Output file for the generated packetdrill script. If --auto-analyze is used, this is treated as a base name.",
)
@click.option(
    "-p",
    "--protocol",
    type=click.Choice(list(SUPPORTED_PROTOCOLS.keys()), case_sensitive=False),
    help="Protocol to filter (default: auto-detect). Ignored if --auto-analyze is used.",
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
    "--auto-analyze",
    is_flag=True,
    help="Automatically analyze PCAP and generate test scripts for all detected protocols",
)
@click.option(
    "--output-dir",
    default=".",
    help="Output directory for generated scripts when using --auto-analyze",
)
@click.option(
    "--debug/--no-debug",
    default=False,
    help="Enable debug output",
)
def convert(
    pcap_file: str,
    output: Optional[str],
    protocol: Optional[str],
    client_ip: Optional[str],
    server_ip: Optional[str],
    client_port: Optional[int],
    server_port: Optional[int],
    relative_time: bool,
    template: Optional[str],
    auto_analyze: bool,
    output_dir: str,
    debug: bool,
) -> int:
    """
    Convert a PCAP file to Packetdrill test scripts.

    Analyzes the structure of a PCAP file and generates Packetdrill test scripts
    for TCP, UDP, and SCTP protocols with appropriate pre- and post-conditions.

    PCAP_FILE: Path to the input PCAP file
    """
    try:
        if debug:
            click.echo(f"Processing {pcap_file}...")

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

        # Check if we should auto-analyze the PCAP
        if auto_analyze:
            click.echo("Auto-analyzing PCAP file and generating test scripts for all detected protocols...")
            
            # Convert PCAP to multiple packetdrill scripts
            scripts = converter.convert()
            
            # Ensure output directory exists
            os.makedirs(output_dir, exist_ok=True)
            
            # Determine base name for output
            if output:
                base_name = os.path.splitext(output)[0]
            else:
                base_name = os.path.splitext(os.path.basename(pcap_file))[0]
            
            # Write scripts to separate files
            for proto, script in scripts.items():
                output_file = os.path.join(output_dir, f"{base_name}_{proto}.pkt")
                with open(output_file, "w") as f:
                    f.write(script)
                click.echo(f"Generated {proto} packetdrill script: {output_file}")
            
            click.echo(f"Generated {len(scripts)} test scripts successfully.")
        else:
            # Using the original single-protocol conversion
            # Determine output file name if not specified
            if output is None:
                base_name = os.path.splitext(os.path.basename(pcap_file))[0]
                output = f"{base_name}.pkt"
            
            # Convert PCAP to a single packetdrill script
            script = converter.convert_single()
            
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


@cli.command(name="replay")
@click.argument("pcap_file", type=click.Path(exists=True))
@click.option(
    "--output-dir",
    default="./replay_tests",
    help="Output directory for generated replay test scripts",
)
@click.option(
    "--template-dir",
    help="Directory containing custom templates for replay tests",
)
@click.option(
    "--relative-time/--absolute-time",
    default=True,
    help="Use relative timestamps (default: True)",
)
@click.option(
    "--debug/--no-debug",
    default=False,
    help="Enable debug output",
)
def replay(
    pcap_file: str,
    output_dir: str,
    template_dir: Optional[str],
    relative_time: bool,
    debug: bool,
) -> int:
    """
    Generate replay test scripts from complete TCP/SCTP connections in a PCAP file.

    This command analyzes a PCAP file to identify complete TCP connection cycles and
    SCTP association cycles, then generates separate test scripts for each cycle.
    Each generated test is a self-contained Packetdrill script that can be used to
    reproduce the exact network behavior observed in the original capture.

    PCAP_FILE: Path to the input PCAP file
    """
    try:
        if debug:
            click.echo(f"Processing {pcap_file} for replay tests...")

        # Create generator instance
        generator = ReplayTestGenerator(
            pcap_file=pcap_file,
            output_dir=output_dir,
            template_dir=template_dir,
            relative_time=relative_time,
            debug=debug,
        )

        # Generate replay tests
        click.echo("Generating replay test scripts for complete connection cycles...")
        test_scripts = generator.generate_replay_tests()
        
        if not test_scripts:
            click.echo("No complete connection cycles found in the PCAP file.")
        else:
            click.echo(f"Successfully generated {len(test_scripts)} replay test scripts in {output_dir}.")
        
        return 0

    except Exception as e:
        click.echo(f"Error: {e}", err=True)
        if debug:
            import traceback
            traceback.print_exc()
        return 1


def main():
    """Main entry point for the CLI."""
    return cli()


if __name__ == "__main__":
    sys.exit(main())
