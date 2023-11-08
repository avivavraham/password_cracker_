from flask import Flask, request, jsonify
import json
import concurrent.futures
import multiprocessing
import hashlib
import requests
import threading
import time

# TODO: go over all of the code in the minion
# TODO: add error handling
# TODO: add documentation to all methods + TaskQueue
# TODO: add parallelism to the system
# TODO: add read me file


PORT = 5002
MINION_ID = 2
# Master's address
MASTER_ADDRESS = 'http://127.0.0.1:5000'  # Modify the address and port accordingly
CHECK_STATUS_AFTER = 100000
SPLIT = 4  # number of processes to split tasks for.
app = Flask(__name__)


def split_task(min_value, max_value, hashed_password, hashed_password_index):
    # create a split array from the range
    range_for_process = (max_value - min_value + 1) // SPLIT
    split_of_range = [(min_value + i * range_for_process, min_value + (i + 1) * range_for_process,
                       hashed_password, hashed_password_index) for i in range(SPLIT - 1)]
    split_of_range.append((split_of_range[-1][1], max_value, hashed_password, hashed_password_index))
    processes = []
    for i in range(SPLIT):
        p = multiprocessing.Process(target=crack, args=split_of_range[i])
        processes.append(p)
    for p in processes:
        p.start()
    for p in processes:
        p.join()
    # after all the processes have done we will request a new task from the master.
    get_task_from_master()


def get_task_from_master():
    try:
        response = requests.get(MASTER_ADDRESS + '/get_task')
        if response.status_code == 200:
            task_details = response.json()
            # Process the received task details
            if "data" in task_details:
                # Extract the required task details
                task_id = task_details['id']
                print(f"getting task {task_id} from the master")
                task_details = json.loads(task_details['data'])
                min_value = task_details["min_value"]
                max_value = task_details["max_value"]
                hashed_password = task_details["hashed_password"]
                hashed_password_index = task_details["hashed_password_index"]
                # split the task concurrently between different processes.
                split_task(min_value, max_value, hashed_password, hashed_password_index)
            else:
                print("Incomplete task details received")
                print(task_details)
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


def receive_password_status(hashed_password, hashed_password_index):
    master_status_url = MASTER_ADDRESS + '/receive_password_status'
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
            if result["already_solved"]:
                return True, " "
            return False, f"keep looking for {hashed_password_index}"
        else:
            # Handle other scenarios based on the received data
            return False, "No status received"
    else:
        # Handle other status codes if needed
        return False, f"Request failed with status code: {response.status_code}"


def send_password_to_master(password, hashed_password, hashed_password_index):
    print(f"found a match with: {password}")
    # Endpoint details of the master
    master_endpoint = MASTER_ADDRESS + '/receive_password'

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
            return True
        else:
            print("Failed to send password to the master.")
            # TODO: check if to send again or the password been already found
            return False
    except requests.exceptions.RequestException as e:
        print(f"Error sending password to the master: {e}")
        return False


def crack(min_range, max_range, hashed_password, hashed_password_index):
    """
    this function iterates over the range to found the password that matches the hashed_password
    :param hashed_password_index:
    :param max_range: the maximum range we want to iterate for
    :param min_range: the minimum range we want to iterate for
    :param hashed_password: the MD5 hash we are looking to find a match for
    """
    halt = False
    for i in range(min_range, max_range):
        # once in a while, the minion will look up to see if there was a stop message from the Master
        if i == min_range + CHECK_STATUS_AFTER:
            try:
                halt, msg = receive_password_status(hashed_password, hashed_password_index)
                if not halt:
                    print(msg)
            except requests.RequestException as e:
                # Handle connection errors or exceptions
                return f"Connection error: {e}"
        #minion has found a match
        if generate_md5_digest(format_phone_number(i)) == hashed_password:
            print("CRACKED!")
            password = format_phone_number(i)
            halt = send_password_to_master(password, hashed_password, hashed_password_index)
        if halt:
            break


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
        cracking_thread = threading.Thread(target=split_task,
                                           args=(min_value, max_value, hashed_password, hashed_password_index))
        cracking_thread.start()
        return jsonify({"message": "received task successfully"})

    return jsonify({"message": "data format is incorrect."})


if __name__ == '__main__':
    app.run(debug=False, port=PORT)  # Change the port number for each minion
