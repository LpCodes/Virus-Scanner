# Virus Scanner

This is a simple Python program that allows you to scan a file for viruses using the VirusTotal API.

## Requirements

- Python 3.x
- [PySimpleGUI](https://pypi.org/project/PySimpleGUI/)
- [requests](https://pypi.org/project/requests/)

## Setup

1. Sign up for a [VirusTotal API key](https://www.virustotal.com/gui/join-us).
2. Clone this repository to your local machine:

   ```
   git clone https://github.com/YOUR_USERNAME/virus-scanner.git
   ```

3. Install the required Python packages:

   ```
   pip install PySimpleGUI requests
   ```

## Setting up the VT_API_KEY environment variable

### On Windows

1. Open the command prompt by pressing the Windows key + R and typing `cmd`, then press Enter.
2. Type `setx /M VT_API_KEY <your-api-key>` and press Enter. This will set the `VT_API_KEY` environment variable to your API key.
3. Verify that the environment variable has been set correctly by typing `echo %VT_API_KEY%` and pressing Enter. This should print the value of the `VT_API_KEY` environment variable.

### On Linux

1. Open a terminal window.
2. Type `export VT_API_KEY=<your-api-key>` and press Enter. This will set the `VT_API_KEY` environment variable to your API key.
3. Verify that the environment variable has been set correctly by typing `echo $VT_API_KEY` and pressing Enter. This should print the value of the `VT_API_KEY` environment variable.

## Usage

To run the program, navigate to the directory where the `scanner.py` script is located and run:

```
python scanner.py
```

The program will open a window with a button to select a file for scanning. Once you select a file and click the "Scan" button, the program will send the file to VirusTotal for scanning and print out the results.

## Contributing

If you find a bug or have a feature request, please open an issue on GitHub.  Any assistance in improving the script will be helpful.

## License

This project is licensed under the MIT License. See the [LICENSE](LICENSE) file for details.
