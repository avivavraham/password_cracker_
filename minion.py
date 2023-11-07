from flask import Flask, request, jsonify
import json
import hashlib
import requests
import threading
import time

# TODO: go over all of the code in the minion
# TODO: make sure we can crack few words
# TODO: add a new minion to the system
# TODO: add error handling
# TODO: add documentation to all methods + TaskQueue
# TODO: add parallelism to the system
# TODO: add read me file





PORT = 5001
MINION_ID = 1
# Master's address
MASTER_ADDRESS = 'http://127.0.0.1:5000'  # Modify the address and port accordingly
app = Flask(__name__)


def get_task_from_master():
    try:
        response = requests.get('http://127.0.0.1:5000/get_task')
        if response.status_code == 200:
            task_details = response.json()
            # Process the received task details
            if "min_value" in task_details and "max_value" in task_details and\
                    "hashed_password" in task_details and "hashed_password_index" in task_details:
                # Extract the required task details
                min_value = task_details["min_value"]
                max_value = task_details["max_value"]
                hashed_password = task_details["hashed_password"]
                hashed_password_index = task_details["hashed_password_index"]

                # Use the task details for the minion's operations
                # Example: start the password cracking process using these details
                crack(min_value, max_value, hashed_password, hashed_password_index)
            else:
                print("Incomplete task details received")
        else:
            print(f"Error getting task. Status code: {response.status_code}")
    except requests.exceptions.RequestException as e:
        print(f"Connection error with master: {e}")


def generate_md5_digest(input_string):
    """
    this function generates MD5 hashing for a given string
    :param input_string: a phone number to be hashed
    :return: the MD5 hashed of the input string
    """
    # Convert the input string to bytes before hashing
    input_bytes = input_string.encode('utf-8')

    # Create an MD5 hash object
    md5 = hashlib.md5()

    # Update the hash object with the input bytes
    md5.update(input_bytes)

    # Obtain the MD5 digest in hexadecimal representation
    md5_digest = md5.hexdigest()
    return md5_digest


def crack(min_range, max_range, hashed_password, hashed_password_index):
    """
    this function iterates over the range to found the password that matches the hashed_password
    :param hashed_password_index:
    :param max_range: the maximum range we want to iterate for
    :param min_range: the minimum range we want to iterate for
    :param hashed_password: the MD5 hash we are looking to find a match for
    """
    time.sleep(0.5)
    print(f'minion {MINION_ID} has started cracking the password')
    halt = False
    for i in range(min_range, max_range,):
        # once in a 1000 iteration minion will look up to see if there was a stop message from the Master
        if i % 1000000 == 0:
            try:
                master_status_url = 'http://127.0.0.1:5000/receive_password_status'
                # Send a POST request to the master to check the status of the hashed password
                # Create the data payload in JSON format
                payload = {
                    "hashed_password": hashed_password,
                    "hashed_password_index": hashed_password_index
                }
                response = requests.post(master_status_url, json=payload)

                # Ensure the response is successful (status code 200) and contains JSON data
                if response.status_code == 200:
                    result = response.json()
                    if "already_solved" in result:
                        # If the password is already solved, return the status
                        if result["already_solved"]:  # TODO: STOP working and receive new task
                            halt = True
                    else:
                        # Handle other scenarios based on the received data
                        return "No status received"
                else:
                    # Handle other status codes if needed
                    return f"Request failed with status code: {response.status_code}"
            except requests.RequestException as e:
                # Handle connection errors or exceptions
                return f"Connection error: {e}"
        # minion has found a match
        if generate_md5_digest(format_phone_number(i)) == hashed_password:
            password = format_phone_number(i)
            print(f"found a match with: {password}")
            halt = True
            # Endpoint details of the master
            master_endpoint = f'http://127.0.0.1:5000/receive_password'

            # Information of the found password
            password_data = {
                "password": password,
                "hashed_password": hashed_password,
                "hashed_password_id": hashed_password_index,
                "minion_id": MINION_ID,
                "port": PORT
            }
            # Sending the found password to the master
            try:
                response = requests.post(master_endpoint, json=password_data)
                if response.status_code == 200:
                    print("Password sent successfully to the master.")
                else:
                    print("Failed to send password to the master.")
            except requests.exceptions.RequestException as e:
                print(f"Error sending password to the master: {e}")
        if halt:
            break
    if not halt:
        # minion has not found the password for that range, minion will ask for a new task.
        get_task_from_master()


def format_phone_number(number):
    """
    :param number: 8 digits of the phone number suffix to be processed
    :return: phone number with the shape of: 05X-XXXXXXX
    """
    # Ensure the number is within a seven-digit range
    formatted_number = str(number).zfill(8)[-8:]

    # Format the number as 05X-XXXXXXX
    phone_number = f"05{formatted_number[:1]}-{formatted_number[1:]}"
    return phone_number


def send_response_to_master(response_data):
    """
    Sends the cracked password response to the master server.

    Args:
    response_data (dict): A dictionary containing the cracked password information.

    Returns:
    JSON: Message indicating the success of sending the response to the master.
    """
    try:
        response = requests.post(f"{MASTER_ADDRESS}/receive_password", json=response_data)
        if response.status_code == 200:
            return jsonify({"message": "Password response sent to the master successfully."})
        else:
            return jsonify({"message": f"Failed to send password response. Status code: {response.status_code}"})
    except requests.exceptions.RequestException as e:
        return jsonify({"message": f"Error sending password response to the master: {e}"})


@app.route('/receive_task', methods=['POST'])
def receive_task():
    """
    Endpoint to receive a task from the master server.

    Expected JSON Structure:
    {
        "min_value": start_range,
        "max_value": end_range,
        "hashed_password": "hashed_password_string",
        "hashed_password_index": "hashed_password_index"
    }

    Notes:
    - The minion receives a task from the master with the range of values to process.
    - It iterates through the range, calculates the hash for each value, and checks if it matches the provided hashed password.
    - If a matching password is found, it communicates back the solution to the master.

    Returns:
    JSON: Message indicating success or failure of finding the password.
    """
    data = request.get_json()
    if data:
        min_value = data.get("min_value")
        max_value = data.get("max_value")
        hashed_password = data.get("hashed_password")
        hashed_password_index = data.get("hashed_password_index")
        cracking_thread = threading.Thread(target=crack,
                                           args=(min_value, max_value, hashed_password, hashed_password_index))
        cracking_thread.start()
        return jsonify({"message": "received task successfully"})

    return jsonify({"message": "data format is incorrect."})


@app.route('/password1', methods=['GET'])
def send_password_to_master():
    # Define the fixed password to be sent
    fixed_password_data = {
        "password": '0500000023',
        "hashed_password": '09bdfd47607d878bf11a1b38400fd480',
        "hashed_password_id": 0,
        "minion_id": f"{MINION_ID}",
        "port": f"{PORT}"
    }

    # Send the fixed password data to the master's /receive_password endpoint
    try:
        response = requests.post('http://127.0.0.1:5000/receive_password',
                                 json=fixed_password_data)
        if response.status_code == 200:
            return jsonify({"message": "Password sent to master successfully"})
        else:
            return jsonify({"message": "Failed to send password to master"})
    except requests.RequestException as e:
        return jsonify({"message": f"Error: {e} - Failed to communicate with master"})


@app.route('/')
def welcome():
    """
    Welcome screen endpoint.
    Displays a welcome message when the minion server is accessed.
    """
    return "Welcome to the Minion Server!"


if __name__ == '__main__':
    app.run(debug=True, port=PORT)  # Change the port number for each minion
