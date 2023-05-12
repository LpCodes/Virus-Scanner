import os
import requests
import PySimpleGUI as sg
import time

# Set the API key for VirusTotal
API_KEY = os.getenv('VT_API_KEY')


def scan_file(file_path):
    try:
        # Open the file and read its contents
        with open(file_path, 'rb') as f:
            file_content = f.read()

        # Send the file to VirusTotal for scanning
        url = 'https://www.virustotal.com/vtapi/v2/file/scan'
        params = {'apikey': API_KEY}
        files = {'file': ('file', file_content)}
        response = requests.post(url, files=files, params=params)

        # Get the scan ID from the response
        scan_id = response.json()['scan_id']

        # Check the scan report every 5 seconds until it's complete
        while True:
            time.sleep(5)
            response = requests.get(
                'https://www.virustotal.com/vtapi/v2/file/report',
                params={'apikey': API_KEY, 'resource': scan_id}
            )
            result = response.json()
            if 'scan_date' in result and result['scan_date'] != '1970-01-01 00:00:00':
                break

        # Print the scan results
        sg.Print('Scan Results:')
        for scanner, result in result['scans'].items():
            sg.Print(f'{scanner}: {result["result"]}')
    except Exception as e:
        sg.Print(f'Error: {e}')
        pass


def main():
    # Create the window layout
    layout = [
        [sg.Text('Select a file to scan for viruses:')],
        [sg.Input(key='file_path', enable_events=True, visible=False), sg.FileBrowse()],
        [sg.Button('Scan')],
        [sg.Output(size=(80, 20))]
    ]

    # Create the window
    window = sg.Window('Virus Scanner', layout)

    # Event loop
    while True:
        event, values = window.read()

        # Handle window events
        if event == sg.WIN_CLOSED:
            break
        elif event == 'file_path':
            file_path = values['file_path']
        elif event == 'Scan':
            file_path = values['file_path']
            if not os.path.isfile(file_path):
                sg.Print('Error: Please select a valid file.')
            else:
                sg.Print(f'Scanning file: {file_path} Please wait ..')
                scan_file(file_path)

    # Close the window
    window.close()


if __name__ == '__main__':
    main()
