#!/usr/bin/env python3
# -*- coding: utf-8 -*-

"""
LCP Decryptor Tool
Decrypts LCP (Licensed Content Protection) protected PDFs.

Usage:
    lcpdecrypt.py [--debug] [<lcpl_file>]
    lcpdecrypt.py (-h | --help)
    lcpdecrypt.py --version

Options:
    -h --help     Show this help message
    --version     Show version
    --debug       Enable debug output
"""

import json
import base64
import hashlib
import os
import sys
from pathlib import Path
import binascii
from zipfile import ZipFile
import argparse
from typing import Optional
from getpass import getpass
import logging
from rich.console import Console
from rich.logging import RichHandler
from rich.progress import Progress, SpinnerColumn, TextColumn, BarColumn, TaskProgressColumn
from rich.prompt import Prompt
from rich import print as rprint

__version__ = '1.0.0'

class LCPDecryptor:
    """Main decryptor class for LCP protected content."""
    
    def __init__(self, lcpl_path: str, passphrase: str, debug: bool = False):
        """Initialize the decryptor with LCPL file path and passphrase."""
        self.lcpl_path = Path(lcpl_path).resolve()
        self.passphrase = passphrase
        self.setup_logging(debug)
        self.console = Console()

    def setup_logging(self, debug: bool):
        """Configure logging with rich output."""
        level = logging.DEBUG if debug else logging.INFO
        logging.basicConfig(
            level=level,
            format="%(message)s",
            handlers=[RichHandler(rich_tracebacks=True)]
        )
        self.log = logging.getLogger("lcpdecrypt")

    def _derive_content_key(self, encrypted_key_data: str, algorithm: str) -> bytes:
        """Derive the content key using the passphrase and algorithm."""
        try:
            with Progress(
                SpinnerColumn(),
                TextColumn("[bold blue]Deriving content key...", justify="right"),
                transient=True
            ) as progress:
                task = progress.add_task("", total=None)
                
                # Hash the passphrase using SHA-256
                hashed_pass = hashlib.sha256(self.passphrase.encode('utf-8')).hexdigest()
                self.log.debug(f"Generated passphrase hash")

                # Apply profile-specific transformation
                if algorithm == "http://readium.org/lcp/basic-profile":
                    transformed_hash = hashed_pass
                else:
                    # Profile 1.0 transform
                    masterkey = "b3a07c4d42880e69398e05392405050efeea0664c0b638b7c986556fa9b58d77b31a40eb6a4fdba1e4537229d9f779daad1cc41ee968153cb71f27dc9696d40f"
                    masterkey = bytearray.fromhex(masterkey)
                    current_hash = bytearray.fromhex(hashed_pass)
                    
                    for byte in masterkey:
                        current_hash.append(byte)
                        current_hash = bytearray(hashlib.sha256(current_hash).digest())
                    transformed_hash = binascii.hexlify(current_hash).decode("latin-1")

                self.log.debug("Key transformation complete")

                # Decrypt the content key
                key_data = base64.b64decode(encrypted_key_data)
                key_bytes = bytes.fromhex(transformed_hash)
                from Crypto.Cipher import AES
                cipher = AES.new(key_bytes[:32], AES.MODE_CBC, key_data[:16])
                content_key = cipher.decrypt(key_data[16:])
                
                # Remove padding if present
                if len(content_key) > 0:
                    padding_len = content_key[-1]
                    if 0 < padding_len <= 16:
                        content_key = content_key[:-padding_len]

                progress.update(task, advance=1)
                return content_key[:32]  # Ensure 32-byte key length

        except Exception as e:
            self.log.error(f"Key derivation failed: {str(e)}")
            raise

    def _decrypt_pdf(self, encrypted_data: bytes, content_key: bytes) -> bytes:
        """Decrypt the PDF content."""
        try:
            if len(encrypted_data) < 16:
                raise ValueError("Invalid encrypted data size")

            # Extract IV and content
            iv = encrypted_data[:16]
            encrypted_content = encrypted_data[16:]

            # Add padding if needed
            padding_length = (16 - (len(encrypted_content) % 16)) % 16
            if padding_length > 0:
                encrypted_content += bytes([padding_length] * padding_length)

            # Decrypt content
            from Crypto.Cipher import AES
            cipher = AES.new(content_key, AES.MODE_CBC, iv)
            decrypted = cipher.decrypt(encrypted_content)

            # Remove padding
            if len(decrypted) > 0:
                padding_len = decrypted[-1]
                if 0 < padding_len <= 16:
                    decrypted = decrypted[:-padding_len]

            return decrypted

        except Exception as e:
            self.log.error(f"Decryption failed: {str(e)}")
            raise

    def decrypt(self) -> None:
        """Main decryption process."""
        try:
            with Progress(
                SpinnerColumn(),
                TextColumn("[progress.description]{task.description}"),
                BarColumn(),
                TaskProgressColumn(),
                console=self.console
            ) as progress:
                # Read license file
                progress.add_task("Reading license file...", total=None)
                with open(self.lcpl_path, 'r', encoding='utf-8') as f:
                    license_data = json.load(f)

                # Get encryption details
                encryption_profile = license_data['encryption']['profile']
                encrypted_key = license_data['encryption']['content_key']['encrypted_value']
                
                # Derive content key
                self.log.info("Deriving content key...")
                content_key = self._derive_content_key(encrypted_key, encryption_profile)

                # Process the LCPDF file
                task = progress.add_task("Processing LCPDF file...", total=100)
                lcpdf_path = self.lcpl_path.parent / f"{self.lcpl_path.stem}.lcpdf"
                
                if not lcpdf_path.exists():
                    raise ValueError(f"LCPDF file not found: {lcpdf_path}")

                # Extract and decrypt PDF
                with ZipFile(lcpdf_path, 'r') as zip_file:
                    pdf_name = next(name for name in zip_file.namelist() if name.endswith('.pdf'))
                    progress.update(task, advance=50)
                    
                    encrypted_pdf = zip_file.read(pdf_name)
                    progress.update(task, advance=25)
                    
                    # Decrypt PDF
                    self.log.info("Decrypting PDF...")
                    decrypted_pdf = self._decrypt_pdf(encrypted_pdf, content_key)
                    progress.update(task, advance=25)

                    # Save decrypted PDF
                    output_path = self.lcpl_path.with_name(f"{self.lcpl_path.stem}_decrypted.pdf")
                    output_path.write_bytes(decrypted_pdf)
                    
                    # Extract cover if present
                    if 'default.jpg' in zip_file.namelist():
                        cover_path = self.lcpl_path.parent / f"{self.lcpl_path.stem}_cover.jpg"
                        with open(cover_path, 'wb') as f:
                            f.write(zip_file.read('default.jpg'))

            rprint(f"\n[green]Successfully decrypted PDF:[/green] {output_path}")

        except Exception as e:
            self.log.error(f"Decryption failed: {str(e)}")
            sys.exit(1)

def check_dependencies():
    """Check and install required packages."""
    required = {
        'pycryptodome': 'Crypto',
        'rich': 'rich'
    }
    
    console = Console()
    with console.status("[bold blue]Checking dependencies...") as status:
        for package, import_name in required.items():
            try:
                __import__(import_name)
            except ImportError:
                console.log(f"Installing {package}...")
                import subprocess
                subprocess.check_call([sys.executable, "-m", "pip", "install", package])

def main():
    """Main entry point."""
    # Parse arguments
    parser = argparse.ArgumentParser(description="LCP Decryptor Tool")
    parser.add_argument('lcpl_file', nargs='?', help='Path to LCPL file')
    parser.add_argument('--debug', action='store_true', help='Enable debug output')
    parser.add_argument('--version', action='version', version=f'LCP Decryptor v{__version__}')
    args = parser.parse_args()

    # Show intro
    console = Console()
    console.print(f"\n[bold blue]LCP Decryptor v{__version__}[/bold blue]")
    console.print("[dim]A tool for decrypting LCP protected content[/dim]\n")

    # Check dependencies
    check_dependencies()

    try:
        # Get LCPL file path
        lcpl_path = args.lcpl_file
        if not lcpl_path:
            lcpl_path = Prompt.ask("Enter path to LCPL file")
        lcpl_path = Path(lcpl_path).resolve()
        
        if not lcpl_path.exists():
            console.print(f"[red]Error:[/red] File not found: {lcpl_path}")
            sys.exit(1)

        # Get passphrase
        passphrase = getpass("Enter passphrase: ")
        if not passphrase:
            console.print("[red]Error:[/red] Passphrase is required")
            sys.exit(1)

        # Create decryptor and process
        decryptor = LCPDecryptor(lcpl_path, passphrase, args.debug)
        decryptor.decrypt()

    except KeyboardInterrupt:
        console.print("\n[yellow]Operation cancelled by user[/yellow]")
        sys.exit(0)
    except Exception as e:
        console.print(f"\n[red]Error:[/red] {str(e)}")
        sys.exit(1)

if __name__ == '__main__':
    main()