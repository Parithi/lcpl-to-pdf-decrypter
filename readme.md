# LCP Decryptor Tool

A Python tool for decrypting LCP (Licensed Content Protection) protected PDFs. This tool allows you to convert `.lcpl` files into readable PDFs using your passphrase.

## Features

- Decrypts LCP-protected PDFs
- Extracts cover images (if available)
- Progress indicators for long operations
- Debug mode for troubleshooting
- Automatic dependency management
- Clean and professional CLI interface

## Prerequisites

- Python 3.7 or higher
- pip (Python package installer)

The script will automatically install required dependencies (`pycryptodome` and `rich`) if they're not already installed.

## Installation

1. Download the script to your local machine
2. Make sure you have Python installed
3. The script will handle other dependencies automatically

## Usage

There are several ways to use the tool:

### Interactive Mode

Simply run the script and follow the prompts:
```bash
python lcpdecrypt.py
```

### Direct Mode

Provide the LCPL file path as an argument:
```bash
python lcpdecrypt.py path/to/your/file.lcpl
```

### Debug Mode

Enable detailed logging for troubleshooting:
```bash
python lcpdecrypt.py --debug path/to/your/file.lcpl
```

### Help

Show available options:
```bash
python lcpdecrypt.py --help
```

## File Structure

When you decrypt a file, the tool will create:
- `{original_name}_decrypted.pdf`: The decrypted PDF file
- `{original_name}_cover.jpg`: The cover image (if available)

## Common Issues and Solutions

1. **File Not Found Error**
   - Make sure the LCPL file exists at the specified path
   - Check if the path contains spaces (use quotes if necessary)
   - Example: `python lcpdecrypt.py "My Books/my book.lcpl"`

2. **Decryption Failed**
   - Verify that you're using the correct passphrase
   - Ensure the LCPDF file is in the same directory as the LCPL file
   - Make sure both files are named correctly

3. **Dependency Installation Failed**
   - Try manually installing dependencies:
     ```bash
     pip install pycryptodome rich
     ```
   - If you get permission errors, try:
     ```bash
     pip install --user pycryptodome rich
     ```

## Command-Line Options

```
Usage:
    lcpdecrypt.py [--debug] [<lcpl_file>]
    lcpdecrypt.py (-h | --help)
    lcpdecrypt.py --version

Options:
    -h --help     Show this help message
    --version     Show version
    --debug       Enable debug output
```

## How It Works

1. **Input**
   - The tool takes an LCPL file (license file) and your passphrase
   - The LCPDF file should be in the same directory as the LCPL file

2. **Process**
   - Reads the license information
   - Derives the content key using your passphrase
   - Extracts and decrypts the PDF content
   - Also extracts the cover image if available

3. **Output**
   - Creates a decrypted PDF with "_decrypted" suffix
   - Saves the cover image if present
   - Shows progress during the process

## Example Usage

1. Basic usage:
```bash
> python lcpdecrypt.py
Enter path to LCPL file: mybook.lcpl
Enter passphrase: ********

Reading license file... ⠋
[INFO] Deriving content key...
[INFO] Decrypting PDF...
Processing LCPDF file... [######################] 100%

Successfully decrypted PDF: mybook_decrypted.pdf
```

2. With debug output:
```bash
> python lcpdecrypt.py --debug mybook.lcpl
[DEBUG] Generated passphrase hash
[DEBUG] Key transformation complete
[DEBUG] Processing PDF content...
...
```

## Security Note

This tool is designed for legal use with content you have legitimate access to. Always ensure you have the right to decrypt the content and comply with the content provider's terms of service.

## Troubleshooting Tips

1. **Script won't run**
   - Make sure Python is installed and in your PATH
   - Try running with `python3` instead of `python`
   - Check file permissions

2. **LCPDF file not found**
   - The LCPDF file should have the same base name as the LCPL file
   - It should be in the same directory as the LCPL file

3. **Debug mode**
   - Run with `--debug` flag for detailed logs
   - Check the output for specific error messages
   - Look for any file permission issues

## Version History

- 1.0.0 (2025-01-29)
  - Initial release
  - Basic decryption functionality
  - Cover image extraction
  - Progress indicators
  - Debug mode