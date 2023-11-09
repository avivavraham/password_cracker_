from flask import Flask, request, jsonify
import json
import multiprocessing
import hashlib
import requests
import threading

# TODO: add read me file + type hints


PORT = 5002
MINION_ID = 2
MASTER_ADDRESS = 'http://127.0.0.1:5000'  # Modify the address and port to the master server address
CHECK_STATUS_AFTER = 100000  # check status after this amount of iterations
# to make sure we don't look for a password who's been already found.
SPLIT = 4  # number of processes to run concurrently on each task.
app = Flask(__name__)


def split_task(min_value, max_value, hashed_password, hashed_password_index):
    """
    Splits the task of cracking a hashed password range into smaller ranges for concurrent processing.

    Parameters:
    - min_value (int): The minimum value in the range to be processed.
    - max_value (int): The maximum value in the range to be processed.
    - hashed_password (str): The hashed password for which a matching password is sought.
    - hashed_password_index (int): Index of the hashed password being cracked.

    Returns:
    - None: This function initiates multiple processes to crack the hashed passwords.

    Notes:
    - Splits the given range of passwords into smaller ranges for concurrent processing.
    - Initiates multiprocessing for each split range to optimize the password cracking process.
    - Calls the 'crack' function within multiple processes with split ranges as arguments.
    - Upon completion of all processes, requests a new task from the Master server to continue the cracking process.

    Raises:
    - Exception: Raised for any unexpected errors during task splitting or multiprocessing initiation.
    - Additional error handling might be required depending on the specific environment and use case.
    """
    try:
        # Create a split array from the range
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

        # Request a new task from the Master after all processes have completed
        get_task_from_master()

    except Exception as e:
        print(f"Error occurred during task splitting or multiprocessing: {e}")
        # Additional error handling or logging can be added based on the specific requirements.


def get_task_from_master():
    """
        Retrieves a task from the Master server.

        This function sends a request to the Master server to fetch a task for cracking hashed passwords.
        Upon receiving the task details, it processes the received task details and splits the task
        concurrently between different processes for cracking the hashed passwords.

        Returns:
        - None: This function operates on the received task details without returning any value directly.

        Notes:
        - The Master server should provide a response with status code 200 for a successful task retrieval.
        - The received task details should contain specific data including 'id', 'min_value', 'max_value',
          'hashed_password', and 'hashed_password_index'.
        - It triggers 'split_task' to split the task among different processes for cracking the hashed passwords.
        - In case of incomplete or unexpected task details received, appropriate messages are printed for reference.

        Raises:
        - requests.exceptions.RequestException: Raised when there's a connection error with the Master server.
        """
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
            if response.status_code == 203:
                print(response.json())
                return
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
    """
        Sends the solved password to the master for processing.

        Parameters:
        - password (str): The solved password.
        - hashed_password (str): The hashed password.
        - hashed_password_index (int): Index of the hashed password.

        Returns:
        - bool: True if the password is successfully sent to the master; False otherwise.
    """
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
    """
        Sends the solved password to the master for processing.

        Parameters:
        - password (str): The solved password.
        - hashed_password (str): The hashed password.
        - hashed_password_index (int): Index of the hashed password.

        Returns:
        - bool: True if the password is successfully sent to the master; False otherwise.
        """
    master_endpoint = MASTER_ADDRESS + '/receive_password'
    password_data = {
        "password": password,
        "hashed_password": hashed_password,
        "hashed_password_id": hashed_password_index,
        "minion_id": MINION_ID,
        "port": PORT
    }

    try:
        response = requests.post(master_endpoint, json=password_data)
        if response.status_code == 200:
            return True
        elif response.status_code == 422:
            print("Hashed password ID is incorrect.")
            return False
        else:
            print("Failed to send password to the master. Try to send it again.")
            return False
    except requests.exceptions.RequestException as e:
        print(f"Error sending password to the master: {e}")
        return False


def crack(min_range, max_range, hashed_password, hashed_password_index):
    """
    Iterates over a given range to find the password that matches the provided hashed password.

    This function starts from 'min_range' and iterates through the range until 'max_range' to find a match
    for the provided 'hashed_password'. It converts each number within the range to its corresponding format
    using 'format_phone_number' and generates an MD5 hash to compare with the 'hashed_password'.

    Parameters:
    - min_range (int): The minimum value in the range to iterate.
    - max_range (int): The maximum value in the range to iterate.
    - hashed_password (str): The MD5 hash for which a matching password needs to be found.
    - hashed_password_index (int): Index of the hashed password being cracked.

    Returns:
    - If successful, a message will be printed when the function finds a matching password and sends
      it to the Master.
    - If the function receives a stop message or encounters an error, it will halt the cracking process.

    Note:
    - 'CHECK_STATUS_AFTER' is a constant determining the frequency for checking messages from the Master.
    - 'format_phone_number' and other referenced functions must be defined and accessible.
    - The 'send_password_to_master' and 'receive_password_status' functions handle communication with the Master.

    Raises:
    - requests.RequestException: Raised when there's a failure in communication with the Master server.
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
                return f"Request to the master failed: {e}", 500
        # minion has found a match
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


@app.errorhandler(422)
def invalid_data_received(e):
    return f"Unprocessable Entity. Invalid data received. {e}", 422


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
    - It iterates through the range, calculates the hash for each value,
     and checks if it matches the provided hashed password.
    - If a matching password is found, it communicates back the solution to the master.

    Returns:
    JSON: Message indicating success or failure of finding the password.
    """
    try:
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
    except (TypeError, TypeError):
        return invalid_data_received()


@app.route('/suggest_add_address/<minion_address>', methods=['POST'])
def suggest_add_address(minion_address):
    """
    Endpoint for suggesting the minions addresses to be added to the master's list.

    Endpoint URL: /suggest_add_address/<minion_address> (Accepts POST request)
    URL Parameter: minion_address (string)

    Returns:
    - Response from the master server after attempting to suggest adding the address.
    """
    try:
        if not isinstance(minion_address, str):
            return 'The provided address should be a string.', 400

        response = requests.post(f"{MASTER_ADDRESS}/add_minion", json={'new_address': minion_address})
        return response.text, response.status_code

    except requests.RequestException as e:
        return f"Request to the master failed: {e}", 500


if __name__ == '__main__':
    app.run(debug=False, port=PORT)  # Change the port number for each minion
