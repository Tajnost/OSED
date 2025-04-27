
#!/usr/bin/env python3
"""
This script filters a list of ROP gadgets based on a number of conditions.
It reads gadgets from a file ("gadgets.txt") and outputs only those lines
that look like full gadgets (contain "ret" or "retn"), whose starting addresses—
when encoded as 4-byte little-endian—do not contain any bad characters, and which
are not duplicates. The cleaned list is written to "gadgets_filtered.txt".

You can adjust:
  - The list of bad characters (BADCHARS).
  - The criteria for whether a gadget line is “useful” (e.g. must contain "ret").
"""

import re

# ---------------------------------------------------------------------------
# 1. Define the bad characters and safe replacements (if needed).
# In this script we only care about removing any gadget whose
# address bytes contain one of these values.
BADCHARS = [0x00, 0x0A, 0x11, 0x20, 0x28, 0x80, 0x81, 0x86]

# ---------------------------------------------------------------------------
# 2. Filtration criteria:
# We require that the line (case-insensitive) contains "ret" (or "retn")
# to be considered a complete gadget.
GADGET_MNEMONIC_PATTERN = re.compile(r'\bret\b', re.IGNORECASE)

# Input and output filenames (change if necessary).
input_filename = "C:\\Users\\Uporabnik\\OneDrive\\Desktop\\OSED-Practice\\badfchars\\gadgets.txt"
output_filename = "gadgets_filtered.txt"

# Use a set to remove duplicate lines.
unique_gadgets = set()

with open(input_filename, "r") as infile, open(output_filename, "w") as outfile:
    for line in infile:
        line = line.strip()
        if not line:
            continue  # Skip empty lines

        # Check for a mnemonic "ret" (or "retn") in the line.
        if not GADGET_MNEMONIC_PATTERN.search(line):
            continue  # Skip lines that don’t seem to be complete gadgets

        # Assume that the gadget address is at the start of the line
        # and is separated by a colon. For example:
        #   "0x63102ba1: aam 0x30 ; adc byte [ebx-0x01], ah ; and eax, 0x..."
        parts = line.split(":", 1)
        if len(parts) < 2:
            continue  # Unexpected format; skip this line.

        address_str = parts[0].strip()
        # Ensure the string starts with "0x" (hex address)
        if not address_str.lower().startswith("0x"):
            continue

        try:
            # Convert the hex address to an integer.
            address_int = int(address_str, 16)
        except ValueError:
            continue

        # Convert the address into 4 bytes in little-endian order.
        try:
            address_bytes = address_int.to_bytes(4, byteorder="little")
        except OverflowError:
            continue  # If the conversion fails (e.g. too many bytes), skip.

        # Check if any of the address bytes is in the BADCHARS list.
        if any(byte in BADCHARS for byte in address_bytes):
            continue  # Skip gadgets with unwanted bytes

        # Remove duplicate gadget lines.
        if line in unique_gadgets:
            continue
        unique_gadgets.add(line)

        # Write out this gadget, which meets our criteria.
        outfile.write(line + "\n")

print(f"Filtering complete. {len(unique_gadgets)} gadgets written to '{output_filename}'.")
