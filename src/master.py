from flask import Flask, flash, request, redirect, url_for, jsonify, render_template
from typing import List, Dict, Union
from werkzeug.utils import secure_filename
from taskQueue import TaskQueue
import requests
import os
import hashlib
import threading
import time
import json
import yaml


with open('C:\\Users\\aviva\\OneDrive\\Desktop\\password_cracker_\\config\\config.yaml', 'r') as file:
    config = yaml.safe_load(file)

# please insert the minions addresses here
MASTER = config['MASTER']['address']
# Construct the MINIONS list
MINIONS = [f"{minion['address']}:{minion['port']}" for minion in config['MINIONS']]
UPLOAD_FOLDER = config['UPLOAD_FOLDER']
ALLOWED_EXTENSIONS = config['ALLOWED_EXTENSIONS']
headers = {'Content-Type': 'application/json'}  # Set the Content-Type header

app = Flask(__name__)
app.config['UPLOAD_FOLDER'] = UPLOAD_FOLDER
SOLVING: bool = False  # boolean flag to indicate if the server is currently solving the md5 hashing.
hash_codes: List[str] = []  # List to store hash codes from the uploaded file.
hash_codes_processed: List[str] = []  # List to store the passwords that were founded.
found_passwords: List[bool] = []  # List to indicate the passwords that were founded.
task_queue = TaskQueue()  # task queue for the current unsolved hashed password.
NUMBER_OF_TASKS = config['NUMBER_OF_TASKS']  # cannot be zero.


def allowed_file(filename: str) -> bool:
    """
    Check if the provided filename has an allowed extension.
    Args:
        filename (str): The filename to be checked.
    Returns:
        bool: True if the filename has an allowed extension, False otherwise.
    """
    return '.' in filename and filename.rsplit('.', 1)[1].lower() in ALLOWED_EXTENSIONS


def generate_tasks_for_minions(hashed_password: str, split: int, hashed_password_index: int) -> TaskQueue:
    """
    this function generates {split} amount of tasks for a specific hashed password.
    :param hashed_password_index: the hashed password index to generate tasks for.
    :param hashed_password: the hashed password to generate tasks for.
    :param split: how many tasks to split for.
    :return: queue of tasks for the specific hashed password.
    """
    """
       05X-XXXXXXX is the given inputs. so the range of numbers is from 050-0000000 to 059-9999999
       simplified to: 00000000 up to 99999999 a range of 10**8 options.
       so each one of the minions will get approximately (10**8 / Number_of_minions) options to check.
    """
    task_queue_for_distribute = TaskQueue()
    options = 10 ** 8 // split
    for j in range(split):
        start_of_range = j * options
        if j == split - 1:
            end_of_range = 10 ** 8
        else:
            end_of_range = (j + 1) * options
        task_data = {
            'min_value': start_of_range,
            'max_value': end_of_range,
            'hashed_password': hashed_password,
            'hashed_password_index': hashed_password_index
        }
        # Convert the task_data dictionary to a JSON string
        json_data = json.dumps(task_data)
        # append the task into the queue
        task_queue_for_distribute.add_task(task_id=j, task_data=json_data)
    return task_queue_for_distribute


def distribute_tasks_for_minions(task_queue_to_distribute: TaskQueue) -> None:
    """
        Distributes tasks to multiple minions.

        Args:
        task_queue (TaskQueue): A TaskQueue object containing tasks to be distributed.

        Explanation:
        This function is responsible for distributing tasks to multiple minions for parallel processing.
        It takes a TaskQueue object containing the tasks to be distributed. The minions' addresses and APIs are
        assumed to be set and operational. Minions are expected to have an API to receive tasks. The function
        coordinates the distribution of tasks by sending each task to its respective minion using their API
        endpoints.

        Implementation Notes:
        - The global variable MINIONS should contain a list of addresses for all available minions.
        - This function works in conjunction with the minion API for task reception.
        - The TaskQueue object contains tasks, and this function iterates through the available minions,
          distributing tasks to each minion in the MINIONS list.
        - The method should iterate through each minion address in the MINIONS list and send tasks from
          task_queue to the respective minion API for processing.

        Returns:
        None
        """
    global MINIONS  # Assuming MINIONS contains the list of minion addresses
    for minion_address in MINIONS:
        try:
            task = task_queue_to_distribute.get_first_task()
            if task is not None:
                response = requests.post(minion_address + '/task', data=task["data"], headers=headers)
                if response.status_code == 200:
                    print(f"Task sent to {minion_address} successfully.")
                else:
                    print(f"Error sending task to {minion_address}. Status code: {response.status_code}")
        except requests.exceptions.RequestException as e:
            print(f"Connection error with minion {minion_address}: {e}")


def validate_password(hashed_password: str, password: str) -> bool:
    """
    Validates whether a password matches its MD5 hash.

    Args:
    hashed_password (str): The hashed password.
    password (str): The original password to be validated.

    Returns:
    bool: True if the hashed password matches the MD5 hash of the provided password, otherwise False.
    """

    # Hash the password using MD5
    hashed_input_password = hashlib.md5(password.encode()).hexdigest()

    # Compare the provided hashed password with the newly hashed input password
    if hashed_input_password == hashed_password:
        return True
    else:
        return False


def get_password(hashed_password_index: int, hashed_password: str) -> None:
    """
    Searches for the password that matches the hashed password using a distributed task system.

    This function initiates a search for the password corresponding to the provided hashed password
    index and the hashed password. It utilizes a task distribution mechanism to search for the password
    by assigning tasks to multiple minions (or workers) within a distributed system.

    Parameters:
    - hashed_password_index (int): Index of the hashed password being searched.
    - hashed_password (str): Hashed password that needs to be matched to find the original password.

    Global Variables Used:
    - NUMBER_OF_TASKS (int): Represents the number of tasks generated for minions.
    - task_queue (list): Holds the tasks generated for the minions.

    Task Distribution Process:
    - task_queue: Generates tasks for minions using the 'generate_tasks_for_minions()' function,
      distributing tasks related to the provided hashed password among multiple workers.
    - distribute_tasks_for_minions(): Assigns the generated task queue to the minions for execution.

    Progress Monitoring:
    - Prints the distribution of tasks to minions for the specific hashed word index.
    - Executes a loop to monitor if the password is found by the minions. Waits until the corresponding
      password is discovered before proceeding.
    - Utilizes time.sleep() to avoid constant checking and reduce processing overhead.

    Output:
    - Upon discovery of the password, prints a message indicating the found password for the specific
      hashed password index.

    Note:
    - This function assumes the existence and functionality of 'generate_tasks_for_minions()' and
      'distribute_tasks_for_minions()' functions, along with 'found_passwords' (a data structure used to
      track the discovered passwords).

    Returns:
    None
    """
    global NUMBER_OF_TASKS, task_queue
    task_queue = generate_tasks_for_minions(hashed_password, NUMBER_OF_TASKS, hashed_password_index)
    distribute_tasks_for_minions(task_queue)
    print(f"Tasks distributed to minions for hashed word number {hashed_password_index}")
    while not found_passwords[hashed_password_index]:
        time.sleep(0.5)
    print(f"Found password number {hashed_password_index}")


def code_cracking_task():
    """
    Crack the hash codes to passwords and save passwords to a file ('output.txt') in case of an error.

    This function attempts to crack the hash codes provided in the global variables hash_codes
    using the associated passwords list. It updates the global variable SOLVING to False after
    the cracking process is complete.

    It iterates through the hash codes and tries to find their corresponding passwords by
    calling the get_password function. If any error occurs during the cracking process for
    a specific hash code, it will be caught and printed, allowing the function to continue
    attempting to crack the remaining codes.

    In the event of an error, the function writes the attempted passwords to a file named
    'output.txt' to provide a record of the cracking attempt.

    Note:
    - Requires get_password() function to be defined and accessible.
    - Relies on global variables: hash_codes, passwords, SOLVING.

    Raises:
    - Exception: Any unexpected errors during the cracking process.

    Returns:
    None
    """
    global hash_codes, hash_codes_processed, SOLVING
    try:
        for i in range(len(hash_codes)):
            get_password(i, hash_codes[i])
        SOLVING = False
        print("Done Cracking The Codes!")
    except Exception as e:
        print(f"An error occurred during code cracking: {e}")
        # Further error handling can be added based on the specific exception type
        # For example, log the error, attempt recovery, or raise a custom exception
    finally:
        # Always write passwords to a file, whether an error occurred or not
        passwords = [entry.split(':')[-1].strip() for entry in hash_codes_processed]
        # Write extracted passwords to the 'output.txt' file
        with open('output.txt', 'w') as output_file:
            output_file.write("\n".join(passwords))


@app.route('/task', methods=['GET'])
def get_task():
    """
    Provides tasks for minions to work on from the task queue.

    Explanation:
    This endpoint serves tasks to minions. If tasks are available in the task queue,
     it retrieves the next task and provides it to the requesting minion.
    If the task queue is empty but the password cracking process is still ongoing,
     it responds with a message indicating to try again shortly.

    Returns:
    JSON: Task details for the minion to process or a message for delayed attempt.
    """
    global task_queue
    task = task_queue.get_first_task()
    if SOLVING and task is not None:
        return jsonify(task)
    elif SOLVING:
        return server_overload(None)
    else:
        return jsonify({"message": f"Master is not solving anything at the moment, redirect to {MASTER}/"
                                   " in order to upload a new file to solve",
                        "link": "/"}), 203


# Function to serve the uploaded file content and success message
@app.route('/uploads/<name>')
def download_file(name: str) -> str:
    """
        Serve the uploaded file to the user.
        Args:
            name (str): The name of the file to be served.
        Returns:
            File response: The uploaded file + File uploaded successfully message.
    """
    global hash_codes, found_passwords, hash_codes_processed, SOLVING
    if os.path.exists(os.path.join(app.config['UPLOAD_FOLDER'], name)):
        with open(os.path.join(app.config['UPLOAD_FOLDER'], name), 'r') as f:
            # Start the code cracking process in a separate thread
            hash_codes = f.read().split('\n')
            hash_codes_processed = hash_codes
            found_passwords = [False for _ in hash_codes_processed]
            message = f'File "{name}" uploaded successfully! The cracking process has started.'
            SOLVING = True
            cracking_thread = threading.Thread(target=code_cracking_task)
            cracking_thread.start()
        return render_template('show_content.html', content=hash_codes_processed, message=message)
    else:
        return 'File Not Found'


@app.route('/status', methods=['POST'])
def receive_password_status() -> Dict[str, Union[bool, List[bool]]]:
    """
    Endpoint to check the status of a hashed password by its index.
    Minions can query to check if a hashed word is already solved or not.

    Expected JSON Structure:
    {
        "hashed_password": "the hashed password"
        "hashed_password_index": "Index of hashed password"
    }

    Notes:
    - Use POST requests for checking the status of a hashed password.
    - The function checks if the provided hashed password index is already solved or not.
    - If the hashed word is solved, returns a flag indicating it's already solved.
    - Minions use this to determine whether they should work on the task or move to the next task.
    - Implement error handling and data validation for received data.

    Returns:
    JSON: Flag indicating if the hashed word is already solved.
    """
    try:
        data = request.get_json()
        if data:
            hashed_password_index = data.get("hashed_password_index")
            if 0 <= hashed_password_index < len(hash_codes):
                # Check if the hashed password index is already solved
                return {"already_solved": found_passwords[hashed_password_index]}

    except (TypeError, KeyError):
        return invalid_data_received(KeyError)


def process_receive_password(data: dict) -> str:
    """
        Process the received password data from minions.

        Parameters:
        data (dict): A dictionary containing password-related information received from the minion.

        Notes:
        - Validates the received password data and checks if the hashed password ID matches with the stored hash_codes.
        - If the password matches with the hashed password and passes validation, it updates the found passwords list.
        - If the hashed password ID is incorrect or out of range, it triggers the 422 error handler.

        Returns:
        str: Success message or error description.
        """
    global hash_codes, found_passwords
    try:
        solved_password = data.get("password")
        hashed_password = data.get("hashed_password")
        hashed_password_id = data.get("hashed_password_id")
        if 0 <= hashed_password_id < len(hash_codes):
            if hash_codes[hashed_password_id] == hashed_password and \
                    validate_password(hashed_password, solved_password):
                if not found_passwords[hashed_password_id]:
                    hash_codes_processed[hashed_password_id] += " ->" + f" Solved successfully" \
                                                                        f"  \u2713 The password is: {solved_password}"
                    found_passwords[hashed_password_id] = True
        return invalid_data_received("hashed_password_id is incorrect")
    except TypeError as e:
        return invalid_data_received(e)


@app.route('/password', methods=['POST'])
def receive_password() -> str:
    """
    Endpoint to receive solved passwords from minions.
    This function will receive updates from the minions when they solve a password hash.

    Expected JSON Structure:
    {
        "password": "05X-XXXXXXX",
        "hashed_password": "hashed_password_string",
        "hashed_password_id": "hashed_password_id",
        "minion_id": "ID or Address of Minion",
        "port": "Minion Port"
    }

    Notes:
    - Use POST requests for sending password updates.
    - Minions send the solved password and hashed password.
    - The function captures the solved password and stores it for further processing or logging.
    - Implement error handling and data validation for received data.

    Returns:
    str: Success message or error description.
    """
    data = request.get_json()
    if data:
        # Create a thread for each request to process it separately
        thread = threading.Thread(target=process_receive_password, args=(data,))
        thread.start()
    return invalid_data_received(None)


@app.route('/content')
def get_updated_content():
    global hash_codes_processed
    return jsonify({'content': hash_codes_processed})


@app.route('/minion', methods=['POST'])
def add_minion():
    """
    Adds a new minion address to the global MINIONS list.

    Endpoint URL: /add_minion (Accepts POST request)
    Request Body (JSON): {'new_address': 'http://new_address:port'}

    Returns:
    - Updated MINIONS list after adding the new address if successful.
    - Error message if the address is already in the MINIONS list or if the input is invalid.
    """
    try:
        data = request.get_json()
        new_address = data.get('new_address')

        if not isinstance(new_address, str):
            return jsonify({'error': 'The provided address should be a string.'}), 400

        if new_address in MINIONS:
            return jsonify({'error': 'The provided address is already in the list of minions.'}), 400

        MINIONS.append(new_address)
        return jsonify({'message': 'New address added successfully', 'updated_minions': MINIONS}), 200

    except Exception as e:
        return jsonify({'error': f"An error occurred while adding the address: {e}"}), 500


@app.route('/', methods=['GET', 'POST'])
def upload_file():
    """
    Handle the file upload process, extract hash codes, and store them in the 'hash_codes' list.
    Returns:
        HTML content: Upload form if method is GET, or redirects to the uploaded file if successful POST request.
    """
    if request.method == 'POST':
        try:
            if 'file' not in request.files:
                flash('No file part')
                return redirect(request.url)
            file = request.files['file']
            if file.filename == '':
                flash('No selected file')
                return redirect(request.url)
            if file and allowed_file(file.filename):
                filename = secure_filename(file.filename)
                file.save(os.path.join(app.config['UPLOAD_FOLDER'], filename))

                # Open the uploaded file and read the hash codes
                with open(os.path.join(app.config['UPLOAD_FOLDER'], filename), 'r') as f:
                    hash_codes.extend(f.read().splitlines())  # Store hash codes in the list

                return redirect(url_for('download_file', name=filename))
            else:
                flash('Invalid file type')
                return redirect(request.url)
        except Exception as e:
            return f"An error occurred: {e}", 500
    return '''
    <!doctype html>
    <title>Upload new File</title>
    <h1>Upload new File</h1>
    <form method=post enctype=multipart/form-data>
      <input type=file name=file>
      <input type=submit value=Upload>
    </form>
    '''


@app.errorhandler(503)
def server_overload():
    return "Service Unavailable. The server is currently overloaded. Please try again later.", 503


@app.errorhandler(404)
def page_not_found():
    """Custom error handling for 404 Not Found error."""
    return "The resource could not be found", 404


@app.errorhandler(422)
def invalid_data_received(e):
    return f"Unprocessable Entity. Invalid data received. {e}", 422


if __name__ == '__main__':
    app.run(debug=config['FLASK']['DEBUG'])
