# Script Ghidra Golang 
### This is a script for Ghidra to load and apply Golang function signatures.

## Features
It can parse JSON files containing Golang definitions.
It can detect and use Golang's basic types, arrays, slices, interfaces, and structs.
It can map Golang function signatures onto Ghidra's function representations.
## Requirements
This script requires Ghidra, a software reverse engineering (SRE) framework.

## How to use
Place the Python script in your Ghidra scripts directory.
Open Ghidra.
Select "Window -> Script Manager".
Browse to the script and click on the "Run" button.
Input
The script uses an out.json file which should be placed in the same directory as the script. This JSON file should contain the Golang definitions.

## Output
The script doesn't produce an output file. Instead, it modifies the current program opened in Ghidra, by mapping Golang function signatures onto Ghidra's function representations.

## Limitations
This script was developed for Ghidra and has been tested only on Windows (amd64 architecture) and Linux (x86 and AARCH64 architectures). It might not work correctly on other platforms.

## Contributing
Contributions are welcome. Please submit a pull request if you have any improvements or bug fixes.

## Contact
If you have any questions, please feel free to contact me at [Mikk pane oma email siia].

## Disclaimer
This script is provided as-is without any warranty. Use it at your own risk.