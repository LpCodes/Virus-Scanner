
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

3. Create a new file called `secrets_key.py` in the same directory as the `scanner.py` script.
4. In `secrets.py`, define a variable called `API_KEY` and set its value to your VirusTotal API key:

   ```
   API_KEY = 'your_api_key_here'
   ```

5. Install the required Python packages:

   ```
   pip install PySimpleGUI requests
   ```

## Usage

To run the program, navigate to the directory where the `scanner.py` script is located and run:

```
python scanner.py
```

The program will open a window with a button to select a file for scanning. Once you select a file and click the "Scan" button, the program will send the file to VirusTotal for scanning and print out the results.

## Contributing

If you find a bug or have a feature request, please open an issue on GitHub. Also Assist In Improving the script .

## License

This project is licensed under the MIT License. See the [LICENSE](LICENSE) file for details.
