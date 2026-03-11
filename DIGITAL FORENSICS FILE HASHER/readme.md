# Digital Forensics File Hasher

A simple Python digital forensics tool that calculates MD5 and SHA256 hashes of files in a directory.

## Purpose

Hashing is used in digital forensics to:

- Verify file integrity
- Detect file tampering
- Identify duplicate files
- Compare files with malware databases

## Features

- Scans all files in a directory
- Calculates MD5 and SHA256 hashes
- Handles large files using chunk reading

## Requirements

Python 3.x

## Usage

Run the script:

python file_hasher.py

Enter the directory you want to scan.

## Example

File: evidence/image.jpg  
MD5: 9e107d9d372bb6826bd81d3542a419d6  
SHA256: d7a8fbb307d7809469ca9abcb0082e4f

## Author

Kelly Ayomide
