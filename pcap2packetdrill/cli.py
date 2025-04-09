#!/usr/bin/env python3
"""
Command Line Interface for PCAP2Packetdrill.

This module provides the command-line interface for the PCAP2Packetdrill tool,
which converts PCAP files into Packetdrill test scripts for TCP, UDP, and SCTP protocols.
It supports both basic conversion and advanced features like automatic protocol detection 
and replay test generation from complete connection cycles.
"""

import os
import sys
import ipaddress
from typing import List, Optional, Dict, Union, Tuple
from pathlib import Path

import click

from pcap2packetdrill import __version__
from pcap2packetdrill.converter import PcapConverter
from pcap2packetdrill.replay_generator import ReplayTestGenerator
from pcap2packetdrill.protocols import SUPPORTED_PROTOCOLS


# Set up common options for better CLI organization
def common_options(f):
    """Common CLI options for multiple commands."""
    f = click.option(
        "--debug/--no-debug",
        default=False,
        help="Enable detailed debug output to help identify issues",
    )(f)
    f = click.option(
        "--relative-time/--absolute-time",
        default=True,
        help="Use relative timestamps starting from 0 (default: True)",
    )(f)
    return f


@click.group()
@click.version_option(version=__version__)
def cli():
    """
    PCAP2Packetdrill - Convert PCAP files to Packetdrill test scripts.
    
    This tool can:
    1. Convert PCAP files to single or multiple protocol-specific test scripts
    2. Generate replay tests from complete TCP connections and SCTP associations
    3. Automatically add appropriate pre-conditions and post-conditions
    
    See the subcommands for specific functionality.
    """
    pass


@cli.command(name="convert")
@click.argument("pcap_file", type=click.Path(exists=True))
@click.option(
    "-o",
    "--output",
    default=None,
    help="Output file for the generated script. If --auto-analyze is used, this is treated as a base name.",
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
    "--template",
    type=click.Path(exists=True, dir_okay=False),
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
    type=click.Path(file_okay=False),
    help="Output directory for generated scripts when using --auto-analyze",
)
@common_options
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
        # Validate PCAP file exists (handled by click.Path(exists=True))
        # but let's also check if it's a real file and not a directory
        if not os.path.isfile(pcap_file):
            raise click.BadParameter(f"'{pcap_file}' is not a file.")

        # Validate IP addresses if provided
        if client_ip:
            try:
                ipaddress.ip_address(client_ip)
            except ValueError:
                raise click.BadParameter(f"Invalid client IP address: {client_ip}")
                
        if server_ip:
            try:
                ipaddress.ip_address(server_ip)
            except ValueError:
                raise click.BadParameter(f"Invalid server IP address: {server_ip}")
                
        # Validate port numbers if provided
        if client_port is not None and not (0 <= client_port <= 65535):
            raise click.BadParameter(f"Invalid client port: {client_port}. Port must be between 0 and 65535.")
            
        if server_port is not None and not (0 <= server_port <= 65535):
            raise click.BadParameter(f"Invalid server port: {server_port}. Port must be between 0 and 65535.")
        
        # Print information about the operation in debug mode
        if debug:
            click.echo(f"Processing {pcap_file}...")
            if protocol:
                click.echo(f"Protocol filter: {protocol}")
            if client_ip or server_ip or client_port is not None or server_port is not None:
                endpoint_info = []
                if client_ip:
                    endpoint_info.append(f"client IP: {client_ip}")
                if client_port is not None:
                    endpoint_info.append(f"client port: {client_port}")
                if server_ip:
                    endpoint_info.append(f"server IP: {server_ip}")
                if server_port is not None:
                    endpoint_info.append(f"server port: {server_port}")
                click.echo(f"Endpoint filters: {', '.join(endpoint_info)}")

        # Create converter instance
        try:
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
        except Exception as e:
            raise click.ClickException(f"Error initializing converter: {e}")

        # Handle auto-analyze mode (generate scripts for all protocols)
        if auto_analyze:
            click.echo("Auto-analyzing PCAP file and generating test scripts for all detected protocols...")
            
            # Validate output directory
            if not os.path.exists(output_dir):
                try:
                    os.makedirs(output_dir, exist_ok=True)
                except OSError as e:
                    raise click.FileError(
                        f"Cannot create output directory {output_dir}", 
                        hint=f"Error: {e}. Check permissions and path validity."
                    )
            elif not os.path.isdir(output_dir):
                raise click.BadParameter(f"Output path '{output_dir}' exists but is not a directory.")
            
            # Convert PCAP to multiple packetdrill scripts
            try:
                scripts = converter.convert()
            except Exception as e:
                raise click.ClickException(f"Error during PCAP conversion: {e}")
            
            if not scripts:
                click.echo("No protocols detected in the PCAP file.")
                return 0
            
            # Determine base name for output files
            if output:
                base_name = os.path.splitext(output)[0]
            else:
                base_name = os.path.splitext(os.path.basename(pcap_file))[0]
            
            # Write scripts to separate files
            for proto, script in scripts.items():
                output_file = os.path.join(output_dir, f"{base_name}_{proto}.pkt")
                try:
                    with open(output_file, "w") as f:
                        f.write(script)
                    click.echo(f"Generated {proto} packetdrill script: {output_file}")
                except IOError as e:
                    click.echo(f"Warning: Could not write to {output_file}: {e}", err=True)
            
            click.echo(f"Generated {len(scripts)} test scripts successfully.")
        else:
            # Single protocol conversion mode
            # Determine output file name if not specified
            if output is None:
                base_name = os.path.splitext(os.path.basename(pcap_file))[0]
                output = f"{base_name}.pkt"
            
            # Convert PCAP to a single packetdrill script
            try:
                script = converter.convert_single()
            except Exception as e:
                raise click.ClickException(f"Error converting PCAP file: {e}")
            
            # Write to output file or stdout
            if output == "-":
                click.echo(script)
            else:
                # Ensure the parent directory exists
                output_dir = os.path.dirname(output)
                if output_dir and not os.path.exists(output_dir):
                    try:
                        os.makedirs(output_dir, exist_ok=True)
                    except OSError as e:
                        raise click.FileError(
                            f"Cannot create directory for output file: {output_dir}", 
                            hint=f"Error: {e}. Check permissions and path validity."
                        )
                
                try:
                    with open(output, "w") as f:
                        f.write(script)
                    click.echo(f"Generated packetdrill script: {output}")
                except IOError as e:
                    raise click.FileError(
                        f"Cannot write to output file: {output}",
                        hint=f"Error: {e}. Check permissions and path validity."
                    )

        return 0

    except click.ClickException:
        # Re-raise Click exceptions as they're already properly formatted
        raise
    except Exception as e:
        # Format other exceptions as Click exceptions
        click.echo(f"Error: {e}", err=True)
        if debug:
            import traceback
            click.echo("Detailed traceback:", err=True)
            traceback.print_exc()
        return 1


@cli.command(name="replay")
@click.argument("pcap_file", type=click.Path(exists=True))
@click.option(
    "--output-dir",
    default="./replay_tests",
    type=click.Path(file_okay=False),
    help="Output directory for generated replay test scripts",
)
@click.option(
    "--template-dir",
    type=click.Path(exists=True, file_okay=False),
    help="Directory containing custom templates for replay tests",
)
@common_options
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
        # Validate PCAP file exists (handled by click.Path(exists=True))
        # but let's also check if it's a real file and not a directory
        if not os.path.isfile(pcap_file):
            raise click.BadParameter(f"'{pcap_file}' is not a file.")
        
        # Validate template directory if provided
        if template_dir and not os.path.isdir(template_dir):
            raise click.BadParameter(f"Template directory '{template_dir}' is not a valid directory.")
        
        # Print information about the operation in debug mode
        if debug:
            click.echo(f"Processing {pcap_file} for replay tests...")
            click.echo(f"Output directory: {output_dir}")
            if template_dir:
                click.echo(f"Template directory: {template_dir}")
            click.echo(f"Using {'relative' if relative_time else 'absolute'} timestamps")

        # Create output directory if it doesn't exist
        if not os.path.exists(output_dir):
            try:
                os.makedirs(output_dir, exist_ok=True)
            except OSError as e:
                raise click.FileError(
                    f"Cannot create output directory {output_dir}", 
                    hint=f"Error: {e}. Check permissions and path validity."
                )
        elif not os.path.isdir(output_dir):
            raise click.BadParameter(f"Output path '{output_dir}' exists but is not a directory.")

        # Create generator instance
        try:
            generator = ReplayTestGenerator(
                pcap_file=pcap_file,
                output_dir=output_dir,
                template_dir=template_dir,
                relative_time=relative_time,
                debug=debug,
            )
        except Exception as e:
            raise click.ClickException(f"Error initializing replay generator: {e}")

        # Generate replay tests
        click.echo("Generating replay test scripts for complete connection cycles...")
        
        try:
            test_scripts = generator.generate_replay_tests()
        except FileNotFoundError as e:
            raise click.FileError(str(e), hint="Make sure the file exists and is accessible.")
        except ValueError as e:
            raise click.ClickException(f"Invalid PCAP file: {e}")
        except IOError as e:
            raise click.FileError(str(e), hint="Check file permissions and disk space.")
        except Exception as e:
            raise click.ClickException(f"Error generating replay tests: {e}")
        
        if not test_scripts:
            click.echo("No complete connection cycles found in the PCAP file.")
        else:
            # Count TCP and SCTP tests
            tcp_count = sum(1 for name in test_scripts.keys() if name.startswith('tcp_'))
            sctp_count = sum(1 for name in test_scripts.keys() if name.startswith('sctp_'))
            
            # Print summary
            click.echo(f"Successfully generated {len(test_scripts)} replay test scripts in {output_dir}:")
            if tcp_count > 0:
                click.echo(f" - {tcp_count} TCP connection {'cycle' if tcp_count == 1 else 'cycles'}")
            if sctp_count > 0:
                click.echo(f" - {sctp_count} SCTP association {'cycle' if sctp_count == 1 else 'cycles'}")
        
        return 0

    except click.ClickException:
        # Re-raise Click exceptions as they're already properly formatted
        raise
    except Exception as e:
        # Format other exceptions as Click exceptions
        click.echo(f"Error: {e}", err=True)
        if debug:
            import traceback
            click.echo("Detailed traceback:", err=True)
            traceback.print_exc()
        return 1


def main():
    """
    Main entry point for the CLI.
    
    Returns the exit code from the CLI command execution.
    """
    try:
        return cli()
    except Exception as e:
        # Catch any unexpected exceptions that weren't handled elsewhere
        click.echo(f"Unexpected error: {e}", err=True)
        return 1


if __name__ == "__main__":
    sys.exit(main())
