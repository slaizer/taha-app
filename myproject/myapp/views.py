import json
import random
import ipaddress
from django.shortcuts import render
from .models import PingStatus
from .models import PingPacket
from django.http import JsonResponse
from django.views.decorators.csrf import csrf_exempt
import json
import json
import random
import ipaddress
import logging
from datetime import datetime
from collections import Counter
from django.shortcuts import render, redirect, get_object_or_404
from django.http import HttpResponse
from django.urls import reverse
from django.contrib.auth import logout
from rest_framework.decorators import api_view
from rest_framework.response import Response
from rest_framework import status
import status
from rest_framework.decorators import api_view
from rest_framework.response import Response
from rest_framework import status
from django.shortcuts import get_object_or_404
from django.shortcuts import render, redirect
from django.http import HttpResponse
from collections import Counter
from django.shortcuts import render, redirect
from django.contrib.auth import logout
from django.http import HttpResponse
from django.urls import reverse
from django.http import HttpResponse
import json
import os
import random
from django.shortcuts import render, redirect
from django.http import HttpResponse
from collections import Counter
import datetime

def load_users():
    with open('users.json', 'r') as f:
        data = json.load(f)
    return data['users']


def load_items():
    try:
        with open('items.json', 'r') as f:
            data = json.load(f)
        return data['items']
    except FileNotFoundError:
        return []


def save_items(items):
    with open('items.json', 'w') as f:
        json.dump({"items": items}, f)


def login_view(request):
    if request.method == 'POST':
        username = request.POST['username']
        password = request.POST['password']

        users = load_users()
        for user in users:
            if user['username'] == username and user['password'] == password:
                request.session['username'] = username
                return redirect('dashboard')

        return HttpResponse("Invalid login credentials.")

    return render(request, 'login.html')


def dashboard_view(request):
    if 'username' not in request.session:
        return redirect('login')

    return render(request, 'dashboard.html', {'username': request.session['username']})


def add_item_view(request):
    if 'username' not in request.session:
        return redirect('login')

    if request.method == 'POST':
        device_name = request.POST['device_name']
        sn = request.POST['sn']
        model = request.POST['model']
        location = request.POST['location']
        status = request.POST['status']
        purchase_date = request.POST['purchase_date']
        contact_number = request.POST['contact_number']
        email_address = request.POST['email_address']

        item = {
            "device_name": device_name,
            "sn": sn,
            "model": model,
            "location": location,
            "status": status,
            "purchase_date": purchase_date,
            "contact_number": contact_number,
            "email_address": email_address
        }
        items = load_items()
        items.append(item)
        save_items(items)
        return redirect('dashboard')

    return render(request, 'add_item.html')


def view_items_view(request):
    if 'username' not in request.session:
        return redirect('login')

    # Load all items
    items = load_items()

    # Filters from GET request
    filters = {
        'device_name': request.GET.get('device_name', '').lower(),
        'sn': request.GET.get('sn', '').lower(),
        'model': request.GET.get('model', '').lower(),
        'location': request.GET.get('location', '').lower(),
        'status': request.GET.get('status', '').lower(),
        'purchase_date': request.GET.get('purchase_date', '').lower(),
        'contact_number': request.GET.get('contact_number', '').lower(),
        'email_address': request.GET.get('email_address', '').lower(),
    }

    # Apply filters dynamically
    for key, value in filters.items():
        if value:  # Apply only if the filter value is provided
            items = [item for item in items if value in item[key].lower()]

    # Aggregate statuses for the doughnut chart
    statuses = [item['status'] for item in items]
    status_count = dict(Counter(statuses))  # Example: {'Active': 5, 'Inactive': 3}

    return render(request, 'view_items.html', {
        'items': items,
        'filters': filters,  # Pass current filters to the template
        'status_count': status_count,
    })
def modify_item_view(request, item_index):
    if 'username' not in request.session:
        return redirect('login')

    items = load_items()
    if request.method == 'POST':
        items[item_index]['device_name'] = request.POST['device_name']
        items[item_index]['sn'] = request.POST['sn']
        items[item_index]['model'] = request.POST['model']
        items[item_index]['location'] = request.POST['location']
        items[item_index]['status'] = request.POST['status']
        items[item_index]['purchase_date'] = request.POST['purchase_date']
        items[item_index]['contact_number'] = request.POST['contact_number']
        items[item_index]['email_address'] = request.POST['email_address']
        save_items(items)
        return redirect('view_items')

    item = items[item_index]
    return render(request, 'modify_item.html', {'item': item, 'item_index': item_index})


def delete_item_view(request, item_index):
    if 'username' not in request.session:
        return redirect('login')

    items = load_items()
    if item_index < len(items):
        del items[item_index]
        save_items(items)
    return redirect('view_items')
# Load users function
import json
from django.shortcuts import render, redirect
from django.http import HttpResponse
from collections import Counter

# Load users function
# Load users function
def load_users():
    with open('users.json', 'r') as f:
        data = json.load(f)
    return data['users']


# Save users function
def save_users(users):
    with open('users.json', 'w') as f:
        json.dump({"users": users}, f)


# Load tickets function
def load_tickets():
    try:
        with open('tickets.json', 'r') as f:
            data = json.load(f)

        # Ensure every ticket has the necessary fields
        for ticket in data['tickets']:
            if 'reference_number' not in ticket:
                ticket['reference_number'] = f"TKT-{random.randint(1000, 9999)}"
            if 'status' not in ticket:
                ticket['status'] = "Pending"  # Default to 'Pending' if status is missing

        return data['tickets']
    except FileNotFoundError:
        return []


# Load comments from JSON file
def load_comments():
    try:
        with open('comments.json', 'r') as f:
            data = json.load(f)
        print("Loaded Comments: ", data['comments'])  # Debug Statement
        return data['comments']
    except FileNotFoundError:
        return []


# Save comments to JSON file
def save_comments(comments):
    with open('comments.json', 'w') as f:
        json.dump({"comments": comments}, f)


# View all tickets with comments attached
def view_tickets_view(request):
    if 'username' not in request.session:
        return redirect('login')

    tickets = load_tickets()
    comments = load_comments()

    # Attach comments to the appropriate ticket by reference number
    for ticket in tickets:
        ticket_reference = ticket.get("reference_number")
        ticket_comments = [comment for comment in comments if comment.get("reference_number") == ticket_reference]
        ticket["comments"] = ticket_comments

    return render(request, 'view_tickets.html', {'tickets': tickets})


# Save tickets function
def save_tickets(tickets):
    with open('tickets.json', 'w') as f:
        json.dump({"tickets": tickets}, f)


# Add new user view
def add_user_view(request):
    if 'username' not in request.session:
        return redirect('login')

    if request.method == 'POST':
        new_username = request.POST['username']
        new_password = request.POST['password']

        users = load_users()
        # Avoid adding duplicate users
        if any(user['username'] == new_username for user in users):
            return HttpResponse("User already exists.")

        users.append({"username": new_username, "password": new_password})
        save_users(users)

        return redirect('dashboard')

    return render(request, 'add_user.html')


# Modify existing user view
def modify_user_view(request, user_index=None):
    if 'username' not in request.session:
        return redirect('login')

    users = load_users()

    if request.method == 'POST':
        modified_username = request.POST['username']
        modified_password = request.POST['password']

        # Avoid duplicate username if changed
        if modified_username != users[user_index]['username'] and any(
                user['username'] == modified_username for user in users):
            return HttpResponse("Username already exists.")

        users[user_index]['username'] = modified_username
        users[user_index]['password'] = modified_password
        save_users(users)

        return redirect('dashboard')

    if user_index is not None:
        user = users[user_index]
        return render(request, 'modify_user.html', {'user': user, 'user_index': user_index})

    # Display all users for selection
    return render(request, 'select_user.html', {'users': users})


# Remove user view
def remove_user_view(request, user_index):
    if 'username' not in request.session:
        return redirect('login')

    users = load_users()
    if user_index < len(users):
        del users[user_index]
        save_users(users)

    return redirect('modify_user')



def edit_user_privileges_view(request, user_index):
    if 'username' not in request.session:
        return redirect('login')

    if request.session.get('privilege') != 'supervisor':
        return HttpResponse("You do not have permission to view this page.")

    users = load_users()
    if request.method == 'POST':
        new_privilege = request.POST.get('privilege', 'normal')
        users[user_index]['privilege'] = new_privilege
        save_users(users)
        return redirect('view_users')

    user = users[user_index]
    return render(request, 'edit_user_privileges.html', {'user': user, 'user_index': user_index})


def logout_view(request):
    # Check if the user is authenticated
    if request.user.is_authenticated:
        # Log out the user
        logout(request)
        # Redirect to the login page after logout
        return redirect(reverse('login'))
    else:
        # If the user is not authenticated, show an error or redirect to login
        return redirect(reverse('login'))

NOTES_FILE = "notes.json"

def load_notes():
    try:
        with open(NOTES_FILE, "r") as f:
            notes = json.load(f)
        print("Loaded Notes:", notes)  # Debug statement
        return notes
    except FileNotFoundError:
        print("Notes file not found. Returning empty.")
        return {}

def save_notes(notes):
    with open(NOTES_FILE, "w") as f:
        json.dump(notes, f)

def notes_view(request):
    if 'username' not in request.session:
        return redirect('login')

    username = request.session['username']
    notes = load_notes()
    user_notes = notes.get(username, [])
    print("Notes for user:", username, user_notes)  # Debug statement

    if request.method == 'POST':
        action = request.POST.get('action')
        note_index = request.POST.get('note_index')
        updated_note = request.POST.get('updated_note')

        if action == 'add':
            note_text = request.POST.get('note', '').strip()
            if note_text:
                user_notes.append(note_text)
                notes[username] = user_notes
                save_notes(notes)

        elif action == 'update' and note_index is not None and updated_note is not None:
            note_index = int(note_index)
            if 0 <= note_index < len(user_notes):
                user_notes[note_index] = updated_note
                notes[username] = user_notes
                save_notes(notes)

        elif action == 'delete' and note_index is not None:
            note_index = int(note_index)
            if 0 <= note_index < len(user_notes):
                user_notes.pop(note_index)
                notes[username] = user_notes
                save_notes(notes)

    return render(request, 'notes.html', {'notes': enumerate(user_notes)})
def subnet_calculator_view(request):
    result = None

    if request.method == 'POST':
        ip_address = request.POST.get('ip_address')
        mask_type = request.POST.get('mask_type')

        try:
            if mask_type == 'subnet_mask':
                subnet_mask = request.POST.get('subnet_mask')
                network = ipaddress.IPv4Network(f"{ip_address}/{subnet_mask}", strict=False)
            elif mask_type == 'prefix':
                prefix = int(request.POST.get('prefix'))
                network = ipaddress.IPv4Network(f"{ip_address}/{prefix}", strict=False)
            else:
                raise ValueError("Invalid mask type selected.")

            # Calculate network details
            result = {
                "network_address": str(network.network_address),
                "broadcast_address": str(network.broadcast_address),
                "num_hosts": network.num_addresses - 2 if network.num_addresses > 2 else 0,
                "first_host": str(network.network_address + 1) if network.num_addresses > 2 else "N/A",
                "last_host": str(network.broadcast_address - 1) if network.num_addresses > 2 else "N/A",
            }
        except ValueError as e:
            result = {"error": str(e)}

    return render(request, 'subnet_calculator.html', {"result": result})
PURCHASE_REQUEST_FILE = "purchase_requests.json"

def load_purchase_requests():
    if os.path.exists(PURCHASE_REQUEST_FILE):
        with open(PURCHASE_REQUEST_FILE, "r") as f:
            return json.load(f)
    return []

def save_purchase_requests(requests):
    with open(PURCHASE_REQUEST_FILE, "w") as f:
        json.dump(requests, f)

def purchase_request_view(request):
    purchase_requests = load_purchase_requests()

    if request.method == 'POST':
        action = request.POST.get('action')
        request_index = request.POST.get('request_index')

        if action == 'add':
            item_name = request.POST['item_name']
            price = float(request.POST['price'])
            currency = request.POST['currency']
            quantity = int(request.POST['quantity'])
            notes = request.POST.get('notes', '')
            supplier = request.POST['supplier']
            phone_number = request.POST['phone_number']
            total_price = price * quantity

            purchase_requests.append({
                "item_name": item_name,
                "price": price,
                "currency": currency,
                "quantity": quantity,
                "total_price": f"{total_price} {currency}",
                "notes": notes,
                "supplier": supplier,
                "phone_number": phone_number,
            })
            save_purchase_requests(purchase_requests)

        elif action == 'delete' and request_index is not None:
            request_index = int(request_index)
            if 0 <= request_index < len(purchase_requests):
                del purchase_requests[request_index]
                save_purchase_requests(purchase_requests)

    return render(request, 'purchase_request.html', {'purchase_requests': enumerate(purchase_requests)})

from rest_framework.decorators import api_view
from rest_framework.response import Response
from rest_framework import status
from datetime import datetime  # Correctly import datetime class
from .models import PingStatus, PingPacket
import logging

logger = logging.getLogger(__name__)

@api_view(['POST'])
def update_ping_status(request):
    """
    API endpoint to receive ping status.
    """
    if request.method == 'POST':
        api_key = request.headers.get('x-api-key')
        if api_key != 'Hellothis-is-myNetwork':
            return Response({'error': 'Unauthorized'}, status=status.HTTP_401_UNAUTHORIZED)

        ip = request.data.get('ip')
        ping_status = request.data.get('status')
        delay = request.data.get('delay', None)

        if not ip or not ping_status:
            return Response({'error': 'Invalid data'}, status=status.HTTP_400_BAD_REQUEST)

        try:
            # Update or create PingStatus record for summary status
            ping_status_obj, created = PingStatus.objects.update_or_create(
                ip_address=ip,
                defaults={'status': ping_status, 'delay': delay, 'last_updated': datetime.now()}
            )

            # Save detailed ping packet information
            PingPacket.objects.create(
                ip_address=ip,
                status=ping_status,
                delay=delay
            )

            return Response({'message': 'Ping status updated successfully'}, status=status.HTTP_200_OK)

        except Exception as e:
            logger.error(f"Failed to update ping status for IP {ip}: {str(e)}")
            return Response({'error': f'Error saving data: {str(e)}'}, status=status.HTTP_500_INTERNAL_SERVER_ERROR)
def ping_packets_view(request):
    """
    View to render all ping packet data.
    """
    ping_packets = PingPacket.objects.all().order_by('-timestamp')  # Get all packets ordered by timestamp
    return render(request, 'ping_packets.html', {'ping_packets': ping_packets})

def ping_history_view(request, ip_address):
    """
    View to render the history of ping packets for a specific IP address.
    """
    ping_history = PingPacket.objects.filter(ip_address=ip_address).order_by('-timestamp')
    context = {
        'ip_address': ip_address,
        'ping_history': ping_history
    }
    return render(request, 'ping_history.html', context)
def ping_packets_json(request):
    """
    View to return all ping packet data as JSON.
    """
    ping_packets = PingPacket.objects.all().order_by('-timestamp')
    data = [
        {
            'ip_address': packet.ip_address,
            'status': packet.status,
            'delay': packet.delay,
            'timestamp': packet.timestamp.strftime("%Y-%m-%d %H:%M:%S")
        } for packet in ping_packets
    ]
    return JsonResponse(data, safe=False)

def ping_history_json(request, ip_address):
    """
    View to return history of ping packets for a specific IP address as JSON.
    """
    ping_history = PingPacket.objects.filter(ip_address=ip_address).order_by('-timestamp')
    data = [
        {
            'ip_address': packet.ip_address,
            'status': packet.status,
            'delay': packet.delay,
            'timestamp': packet.timestamp.strftime("%Y-%m-%d %H:%M:%S")
        } for packet in ping_history
    ]
    return JsonResponse(data, safe=False)

def ping_history_json(request, ip_address):
    """
    View to return history of ping packets for a specific IP address as JSON,
    allowing filtering and saving.
    """
    ping_history = PingPacket.objects.filter(ip_address=ip_address).order_by('-timestamp')

    # Apply filters
    status_filter = request.GET.get('status')
    if status_filter:
        ping_history = ping_history.filter(status=status_filter)

    delay_min = request.GET.get('delay_min')
    delay_max = request.GET.get('delay_max')

    if delay_min:
        ping_history = ping_history.filter(delay__gte=float(delay_min))
    if delay_max:
        ping_history = ping_history.filter(delay__lte=float(delay_max))

    # Prepare data for response
    data = [
        {
            'ip_address': packet.ip_address,
            'status': packet.status,
            'delay': packet.delay,
            'timestamp': packet.timestamp.strftime("%Y-%m-%d %H:%M:%S")
        } for packet in ping_history
    ]

    # Save the filtered data if requested
    if request.method == 'POST':
        file_path = 'ping_history_filtered.json'
        with open(file_path, 'w') as f:
            json.dump(data, f)
        return JsonResponse({'message': 'Filtered data saved successfully', 'file_path': file_path})

    return JsonResponse(data, safe=False)
from django.shortcuts import render, redirect
from django.http import HttpResponse
import json
import ipaddress

IP_FILE = "ips.json"

def load_ips():
    try:
        with open(IP_FILE, 'r') as f:
            return json.load(f).get('ips', [])
    except FileNotFoundError:
        return []

def save_ips(ips):
    with open(IP_FILE, 'w') as f:
        json.dump({"ips": ips}, f, indent=4)

def manage_ips_view(request):
    if 'username' not in request.session:
        return redirect('login')

    ips = load_ips()
    error_message = None

    if request.method == 'POST':
        action = request.POST.get('action')

        if action == 'add':
            ip_address = request.POST.get('ip_address', '').strip()
            location = request.POST.get('location', '').strip()
            status = request.POST.get('status', '').strip().lower()  # Standardizing the value to avoid inconsistencies
            description = request.POST.get('description', '').strip()

            # Validate IP address
            try:
                ipaddress.ip_address(ip_address)
                ips.append({
                    "ip_address": ip_address,
                    "location": location,
                    "status": status,
                    "description": description
                })
                save_ips(ips)
            except ValueError:
                error_message = f"Invalid IP address format: {ip_address}"

        elif action == 'modify':
            ip_index = int(request.POST.get('ip_index', -1))
            if 0 <= ip_index < len(ips):
                ip_address = request.POST.get('ip_address', '').strip()
                location = request.POST.get('location', '').strip()
                status = request.POST.get('status', '').strip().lower()  # Standardizing the value
                description = request.POST.get('description', '').strip()

                try:
                    # Validate IP address format before updating
                    ipaddress.ip_address(ip_address)
                    ips[ip_index] = {
                        "ip_address": ip_address,
                        "location": location,
                        "status": status,
                        "description": description
                    }
                    save_ips(ips)
                except ValueError:
                    error_message = f"Invalid IP address format: {ip_address}"
            else:
                error_message = "Invalid IP index provided for modification."

        elif action == 'delete':
            ip_index = int(request.POST.get('ip_index', -1))
            if 0 <= ip_index < len(ips):
                del ips[ip_index]
                save_ips(ips)
            else:
                error_message = "Invalid IP index provided for deletion."

        if not error_message:
            return redirect('manage_ips')

    return render(request, 'manage_ips.html', {'ips': ips, 'error_message': error_message})

from django.shortcuts import render, redirect
from django.http import HttpResponse
import json

URL_FILE = "external_urls.json"

# Function to load URLs from a JSON file
def load_urls():
    try:
        with open(URL_FILE, 'r') as f:
            return json.load(f).get('urls', [])
    except FileNotFoundError:
        return []

# Function to save URLs to a JSON file
def save_urls(urls):
    with open(URL_FILE, 'w') as f:
        json.dump({"urls": urls}, f, indent=4)

# View to manage external URLs
def manage_urls_view(request):
    if 'username' not in request.session:
        return redirect('login')

    urls = load_urls()
    error_message = None

    if request.method == 'POST':
        action = request.POST.get('action')

        if action == 'add':
            url = request.POST.get('url', '').strip()
            description = request.POST.get('description', '').strip()

            if not url.startswith(('http://', 'https://')):
                error_message = "Invalid URL format. URL must start with 'http://' or 'https://'."
            else:
                urls.append({
                    "url": url,
                    "description": description
                })
                save_urls(urls)

        elif action == 'delete':
            url_index = int(request.POST.get('url_index', -1))
            if 0 <= url_index < len(urls):
                del urls[url_index]
                save_urls(urls)
            else:
                error_message = "Invalid URL index provided for deletion."

        if not error_message:
            return redirect('manage_urls')

    return render(request, 'manage_urls.html', {'urls': urls, 'error_message': error_message})

# View to edit an existing URL
def edit_url_view(request, url_index):
    if 'username' not in request.session:
        return redirect('login')

    urls = load_urls()
    error_message = None

    if 0 <= url_index < len(urls):
        current_url = urls[url_index]
    else:
        return redirect('manage_urls')

    if request.method == 'POST':
        url = request.POST.get('url', '').strip()
        description = request.POST.get('description', '').strip()

        if not url.startswith(('http://', 'https://')):
            error_message = "Invalid URL format. URL must start with 'http://' or 'https://'."
        else:
            urls[url_index] = {
                "url": url,
                "description": description
            }
            save_urls(urls)
            return redirect('manage_urls')

    return render(request, 'edit_url.html', {'url_entry': current_url, 'url_index': url_index, 'error_message': error_message})
from django.shortcuts import render, redirect
import nmap
from django.http import JsonResponse

# View for scanning an IP address
def scan_ip_view(request):
    scan_result = None
    error_message = None

    if request.method == 'POST':
        ip_address = request.POST.get('ip_address', '').strip()

        # Validate the IP address (check if it is in the right format)
        try:
            scanner = nmap.PortScanner()
            scanner.scan(ip_address, arguments='-sP')  # Perform a simple ping scan
            if ip_address in scanner.all_hosts():
                scan_result = scanner[ip_address]
            else:
                error_message = f"No response from {ip_address}. The host may be down or unreachable."
        except Exception as e:
            error_message = f"An error occurred during scanning: {str(e)}"

    return render(request, 'scan_ip.html', {
        'scan_result': scan_result,
        'error_message': error_message,
    })

GYM_FILE = "gym_data.json"

# Load workout data from a file
def load_workouts():
    try:
        with open(GYM_FILE, "r") as f:
            return json.load(f)
    except FileNotFoundError:
        return {"Chest Day": [], "Back Day": [], "Shoulders Day": [], "Leg Day": []}

# Save workout data to a file
def save_workouts(workouts):
    with open(GYM_FILE, "w") as f:
        json.dump(workouts, f, indent=4)

# GYM management view
def gym_management_view(request):
    if request.method == "POST":
        action = request.POST.get("action")
        category = request.POST.get("category")
        workout_name = request.POST.get("workout_name", "").strip()
        repetitions = request.POST.get("repetitions", "").strip()
        weight = request.POST.get("weight", "").strip()  # New weight field
        workout_index = request.POST.get("workout_index")

        workouts = load_workouts()

        if action == "add" and category in workouts:
            # Add a new workout to the selected category
            if workout_name and repetitions and weight:
                workouts[category].append({"name": workout_name, "repetitions": repetitions, "weight": weight})
                save_workouts(workouts)

        elif action == "delete" and category in workouts and workout_index is not None:
            # Delete a workout from the selected category
            workout_index = int(workout_index)
            if 0 <= workout_index < len(workouts[category]):
                del workouts[category][workout_index]
                save_workouts(workouts)

        elif action == "edit" and category in workouts and workout_index is not None:
            # Edit a workout in the selected category
            workout_index = int(workout_index)
            if 0 <= workout_index < len(workouts[category]) and workout_name and repetitions and weight:
                workouts[category][workout_index] = {"name": workout_name, "repetitions": repetitions, "weight": weight}
                save_workouts(workouts)

        return redirect("gym_management")

    # Load workouts for display
    workouts = load_workouts()
    return render(request, "gym_management.html", {"workouts": workouts})


import json
from datetime import datetime, timedelta
import calendar
from django.shortcuts import render, redirect
from django.http import HttpResponse

# File paths for storing data
CASES_FILE = "cases.json"
DUTIES_FILE = "duties.json"


# Load and save functions for cases and duties
def load_cases():
    try:
        with open(CASES_FILE, 'r') as f:
            return json.load(f).get('cases', [])
    except FileNotFoundError:
        return []


def save_cases(cases):
    with open(CASES_FILE, 'w') as f:
        json.dump({"cases": cases}, f, indent=4)


def load_duties():
    try:
        with open(DUTIES_FILE, 'r') as f:
            return json.load(f).get('duties', {})
    except FileNotFoundError:
        return {}


def save_duties(duties):
    with open(DUTIES_FILE, 'w') as f:
        json.dump({"duties": duties}, f, indent=4)


# Combined view to add a new case and display calendar with duties and cases
def case_calendar_view(request):
    if 'username' not in request.session:
        return redirect('login')

    # Handle adding a new case
    if request.method == 'POST' and 'case_name' in request.POST:
        case_name = request.POST['case_name']
        priority = request.POST['priority']
        date = request.POST['date']
        description = request.POST['description']

        case = {
            "case_name": case_name,
            "priority": priority,
            "date": date,
            "description": description
        }
        cases = load_cases()
        cases.append(case)
        save_cases(cases)
        return redirect('case_calendar')

    # Handle calendar view
    duties = load_duties()
    cases = load_cases()
    today = datetime.today()
    year = request.GET.get('year', today.year)
    month = request.GET.get('month', today.month)

    try:
        year = int(year)
        month = int(month)
    except ValueError:
        year = today.year
        month = today.month

    cal = calendar.Calendar(firstweekday=calendar.SUNDAY)
    month_days = cal.itermonthdays(year, month)
    calendar_data = []

    for day in month_days:
        if day == 0:
            calendar_data.append({"day": None, "duties": [], "cases": []})
        else:
            date_str = f"{year:04d}-{month:02d}-{day:02d}"
            duties_for_day = duties.get(date_str, [])
            cases_for_day = [case for case in cases if case['date'] == date_str]
            calendar_data.append({"day": day, "duties": duties_for_day, "cases": cases_for_day})

    context = {
        'year': year,
        'month': month,
        'month_name': calendar.month_name[month],
        'calendar_data': calendar_data,
        'prev_month': (month - 1) if month > 1 else 12,
        'next_month': (month + 1) if month < 12 else 1,
        'prev_year': year if month > 1 else year - 1,
        'next_year': year if month < 12 else year + 1
    }

    return render(request, 'case_calendar.html', context)


# Manage cases view to list, edit, and delete cases
def manage_cases_view(request):
    if 'username' not in request.session:
        return redirect('login')

    cases = load_cases()

    # Handle deletion
    if request.method == 'POST' and 'delete_case' in request.POST:
        case_index = int(request.POST['delete_case'])
        if 0 <= case_index < len(cases):
            del cases[case_index]
            save_cases(cases)
            return redirect('manage_cases')

    context = {
        'cases': enumerate(cases),
    }
    return render(request, 'manage_cases.html', context)

import json
from django.shortcuts import render, redirect
from django.http import JsonResponse
import os

# File path for storing code snippets
CODE_SNIPPETS_FILE = "code_snippets.json"

# Utility functions to load and save snippets
def load_code_snippets():
    try:
        with open(CODE_SNIPPETS_FILE, "r") as f:
            return json.load(f).get("snippets", [])
    except FileNotFoundError:
        return []

def save_code_snippets(snippets):
    with open(CODE_SNIPPETS_FILE, "w") as f:
        json.dump({"snippets": snippets}, f, indent=4)

# View to manage code snippets
def manage_code_snippets_view(request):
    if 'username' not in request.session:
        return redirect('login')

    snippets = load_code_snippets()

    if request.method == 'POST':
        action = request.POST.get('action')
        snippet_index = request.POST.get('snippet_index')

        if action == 'add':
            title = request.POST['title']
            code = request.POST['code']
            description = request.POST.get('description', '')

            snippets.append({
                "title": title,
                "code": code,
                "description": description,
                "author": request.session['username']
            })
            save_code_snippets(snippets)

        elif action == 'delete' and snippet_index is not None:
            snippet_index = int(snippet_index)
            if 0 <= snippet_index < len(snippets):
                del snippets[snippet_index]
                save_code_snippets(snippets)

        return redirect('manage_code_snippets')

    snippets_with_indices = list(enumerate(snippets))
    return render(request, 'manage_code_snippets.html', {'snippets_with_indices': snippets_with_indices})

# View to edit a specific code snippet
def edit_code_snippet_view(request, snippet_index):
    if 'username' not in request.session:
        return redirect('login')

    snippets = load_code_snippets()

    try:
        snippet_index = int(snippet_index)  # Ensure it's an integer
        if request.method == 'POST':
            title = request.POST['title']
            code = request.POST['code']
            description = request.POST.get('description', '')

            if 0 <= snippet_index < len(snippets):
                snippets[snippet_index] = {
                    "title": title,
                    "code": code,
                    "description": description,
                    "author": snippets[snippet_index]['author']
                }
                save_code_snippets(snippets)
                return redirect('manage_code_snippets')
    except (ValueError, IndexError):
        return redirect('manage_code_snippets')

    snippet = snippets[snippet_index]
    return render(request, 'edit_code_snippet.html', {'snippet': snippet, 'snippet_index': snippet_index})
