import requests
import PySimpleGUI as sg
import subprocess
import sqlite3
import winsound
import threading
import time
import re
from collections import defaultdict
from datetime import datetime
from rest_framework import status

# History dictionary
history = defaultdict(list)
# Mute dictionary to track muted IPs
muted_ips = defaultdict(bool)

FLASK_APP_URL = 'http://127.0.0.1:8000/api/update_ping_status/'  # Use HTTP
API_KEY = 'Hellothis-is-myNetwork'  # Your secure API key

def get_ping_status(ip):
    try:
        startupinfo = subprocess.STARTUPINFO()
        startupinfo.dwFlags |= subprocess.STARTF_USESHOWWINDOW
        startupinfo.wShowWindow = subprocess.SW_HIDE
        result = subprocess.run(['ping', '-n', '1', '-w', '1000', ip], stdout=subprocess.PIPE, stderr=subprocess.STDOUT,
                                startupinfo=startupinfo)
        output = result.stdout.decode()
        if "Destination host unreachable" in output:
            return 'down', None
        else:
            match = re.search('Average = (\d+)ms', output)
            if match:
                delay = float(match.group(1))
                return 'up', delay
            else:
                return 'down', None
    except Exception as e:
        return 'down', None
    return 'unknown', None

def send_ping_status_to_flask(ip, status, delay):
    data = {
        'ip': ip,
        'status': status,
        'delay': delay
    }
    headers = {'x-api-key': API_KEY}  # Include the API key in the headers
    try:
        response = requests.post(FLASK_APP_URL, json=data, headers=headers)  # No SSL verification needed
        if response.status_code == 200:
            print(f'Successfully sent data for {ip}')
        else:
            print(f'Failed to send data for {ip}, status code: {response.status_code}')
    except Exception as e:
        print(f'Error sending data for {ip}: {e}')

def start_monitoring():
    conn = sqlite3.connect('ip_database.db')
    c = conn.cursor()
    c.execute('SELECT name, ip_address FROM ips_table')
    ip_data = c.fetchall()
    conn.close()

    layout = []
    for name, ip in ip_data:
        layout.append([sg.Text(f'Ping Status {name} ({ip}):'),
                       sg.Text(size=(15, 1), key=f'-OUTPUT-{ip}-', text_color='white', background_color='black'),
                       sg.Text('Latency:'), sg.Text(size=(10, 1), key=f'-LATENCY-{ip}-'),
                       sg.Button('History', key=f'-HISTORY-{ip}-'),
                       sg.Button('Mute', key=f'-MUTE-{ip}-')])

    window = sg.Window('Ping Status', layout, finalize=True, resizable=True)

    def ping_and_update(ip, name, window):
        while True:
            status, delay = get_ping_status(ip)
            timestamp = datetime.now().strftime('%Y-%m-%d %H:%M:%S')
            if status == 'up':
                window.write_event_value('-UPDATE-', (ip, 'up', delay))
                history[ip].append((timestamp, delay))
            else:
                window.write_event_value('-UPDATE-', (ip, 'down', None))
                if not muted_ips[ip]:
                    winsound.Beep(frequency=2500, duration=1000)
                history[ip].append((timestamp, None))

            # Send the ping status to the Flask app
            send_ping_status_to_flask(ip, status, delay)

            time.sleep(2)

    for name, ip in ip_data:
        threading.Thread(target=ping_and_update, args=(ip, name, window), daemon=True).start()

    while True:
        event, values = window.read()
        if event == sg.WINDOW_CLOSED:
            break
        elif '-UPDATE-' in event:
            ip, status, delay = values['-UPDATE-']
            if status == 'up':
                window[f'-OUTPUT-{ip}-'].update(status, text_color='black', background_color='green')
                window[f'-LATENCY-{ip}-'].update(f'{delay} ms')
            else:
                window[f'-OUTPUT-{ip}-'].update(status, text_color='white', background_color='red')
                window[f'-LATENCY-{ip}-'].update('N/A')
        elif '-HISTORY-' in event:
            ip = event.split('-')[-2]  # Extract the IP from the event string
            history_window_layout = [[sg.Listbox(
                values=[f'{x[0]}: {x[1] if x[1] is not None else "N/A"} ms' for x in reversed(history[ip])],
                size=(60, 20))]]
            history_window = sg.Window(f'Ping history for {ip}', history_window_layout, modal=True)
            history_window.read(close=True)
        elif '-MUTE-' in event:
            ip = event.split('-')[-2]  # Extract the IP from the event string
            muted_ips[ip] = not muted_ips[ip]  # Toggle the mute state
            new_text = 'Unmute' if muted_ips[ip] else 'Mute'
            window[f'-MUTE-{ip}-'].update(new_text)
            if muted_ips[ip]:
                sg.popup(f'Muted alerts for {ip}')
            else:
                sg.popup(f'Unmuted alerts for {ip}')

    window.close()
    sg.Popup("Thanks for using IP Monitor//E3x3E \U0001F47B")

def manage_ips():
    def fetch_ips():
        # Connect to the SQLite database and fetch all data
        conn = sqlite3.connect('ip_database.db')
        c = conn.cursor()
        c.execute('SELECT name, ip_address FROM ips_table')
        data = c.fetchall()
        conn.close()
        return data

    # Layout for the window
    layout = [
        [sg.Text('Name'), sg.Input(key='-NAME-')],
        [sg.Text('IP Address'), sg.Input(key='-IP-')],
        [sg.Button('Submit'), sg.Button('Show All'), sg.Button('Remove Selected'), sg.Button('Exit')],
        [sg.Listbox(values=[], size=(60, 10), key='-LISTBOX-')]
    ]

    # Create the window
    window = sg.Window('Manage IP Addresses', layout)

    while True:
        event, values = window.read()
        # End program if user closes window or presses the Exit button
        if event == sg.WINDOW_CLOSED or event == 'Exit':
            break
        if event == 'Submit':
            name = values['-NAME-']
            ip = values['-IP-']
            # Connect to the SQLite database and insert the data
            conn = sqlite3.connect('ip_database.db')
            c = conn.cursor()
            c.execute('INSERT INTO ips_table VALUES (?, ?)', (name, ip))
            conn.commit()
            conn.close()
            sg.popup('Data inserted successfully!')
        if event == 'Show All':
            data = fetch_ips()
            window['-LISTBOX-'].update(data)
        if event == 'Remove Selected':
            selected = values['-LISTBOX-'][0]
            name, ip = selected[0], selected[1]
            # Connect to the SQLite database and remove the selected data
            conn = sqlite3.connect('ip_database.db')
            c = conn.cursor()
            c.execute('DELETE FROM ips_table WHERE name = ? AND ip_address = ?', (name, ip))
            conn.commit()
            conn.close()
            sg.popup('Data removed successfully!')

    window.close()

layout = [
    [sg.Text('Login Page')],
    [sg.Button('Start Monitoring')],
    [sg.Button('IP Management')]
]

window = sg.Window('Login Page', layout)

while True:
    event, values = window.read()
    if event == sg.WINDOW_CLOSED:
        break
    elif event == 'Start Monitoring':
        window.close()
        start_monitoring()
    elif event == 'IP Management':
        window.close()
        manage_ips()

window.close()
