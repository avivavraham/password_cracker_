from flask import Flask, flash, request, redirect, url_for, jsonify, render_template
from werkzeug.utils import secure_filename
from taskQueue.taskQueue import TaskQueue
import requests
import os
import hashlib
import threading
import time
import json

# TODO: go over all of the code in the master
# TODO: make sure we can crack few words
# TODO: add error handling
# TODO: add documentation to all methods + TaskQueue
# TODO: add concurrent to the system
# TODO: add read me file


MINIONS = ['http://127.0.0.1:5001']  # http://127.0.0.1:5002 for the second minion.
UPLOAD_FOLDER = 'C:\\Users\\aviva\\OneDrive\\Desktop\\password_cracker_\\input_files'
ALLOWED_EXTENSIONS = {'txt'}
headers = {'Content-Type': 'application/json'}  # Set the Content-Type header

app = Flask(__name__)
app.config['UPLOAD_FOLDER'] = UPLOAD_FOLDER

SOLVING = False  # boolean flag to indicate if the server is currently solving the md5 hashing.
hash_codes = []  # List to store hash codes from the uploaded file
passwords = []  # List to store the passwords that were founded
found_passwords = []  # List to indicate the passwords that were founded
task_queue = TaskQueue()  # task queue for the current unsolved hashed password
NUMBER_OF_TASKS = 10


def allowed_file(filename):
    """
    Check if the provided filename has an allowed extension.
    Args:
        filename (str): The filename to be checked.
    Returns:
        bool: True if the filename has an allowed extension, False otherwise.
    """
    return '.' in filename and filename.rsplit('.', 1)[1].lower() in ALLOWED_EXTENSIONS


def generate_tasks_for_minions(hashed_password, split, hashed_password_index):
    """
    this function generates {split} amount of tasks for a specific hashed password.
    :param hashed_password_index: the hashed password index to generate tasks for.
    :param hashed_password: the hashed password to generate tasks for.
    :param split: how many tasks to split for.
    :return: queue of tasks for the specific hashed password.
    """
    task_queue = TaskQueue()
    """
       05X-XXXXXXX is the given inputs. so the range of numbers is from 050-0000000 to 059-9999999
       simplified to: 00000000 up to 99999999 a range of 10**8 options.
       so each one of the minions will get approximately (10**8 / Number_of_minions) options to check.
    """
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
        task_queue.add_task(task_id=j, task_data=json_data)
    return task_queue


def distribute_tasks_for_minions(task_queue_to_distribute):
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
                # Assuming the minion's API endpoint is '/receive_task'
                response = requests.post(minion_address + '/receive_task', data=task["data"], headers=headers)
                if response.status_code == 200:
                    print(f"Task sent to {minion_address} successfully.")
                else:
                    print(f"Error sending task to {minion_address}. Status code: {response.status_code}")
        except requests.exceptions.RequestException as e:
            print(f"Connection error with minion {minion_address}: {e}")


def validate_password(hashed_password, password):
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


def get_password(hashed_password_index, hashed_password, output_file):
    """
    this function search for the password that matches the hashed password.
    :param output_file: the file we creating with all of the solved passwords
    :param hashed_password_index: hashed password index we are searching
    :param hashed_password: hashed password we are searching
    """
    global NUMBER_OF_TASKS, task_queue
    task_queue = generate_tasks_for_minions(hashed_password, NUMBER_OF_TASKS, hashed_password_index)
    distribute_tasks_for_minions(task_queue)
    print(f"Tasks distributed to minions for hashed word {hashed_password_index}")
    while not found_passwords[hashed_password_index]:
        # TODO: try and find the passwords
        time.sleep(0.2)


def code_cracking_task():
    global hash_codes, passwords, SOLVING
    for i in range(len(hash_codes)):
        get_password(i, hash_codes[i], passwords)
    SOLVING = False


@app.route('/get_task', methods=['GET'])
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
    if not SOLVING:
        return jsonify({"message": "Master is not solving anything at the moment, redirect to 'link'"
                                   " in order to upload a new file to solve",
                        "link": "/"}), 203
    if task_queue.get_first_task() is None:
        return jsonify({"message": "Tasks are being processed, try again shortly"}), 202
    else:
        # Get a task from the tasks_queue and provide it to the minion
        task = task_queue.get_first_task()
        return jsonify(task)


# Function to serve the uploaded file content and success message
@app.route('/uploads/<name>')
def download_file(name):
    """
        Serve the uploaded file to the user.
        Args:
            name (str): The name of the file to be served.
        Returns:
            File response: The uploaded file + File uploaded successfully message.
    """
    global hash_codes, found_passwords, passwords, SOLVING
    if os.path.exists(os.path.join(app.config['UPLOAD_FOLDER'], name)):
        with open(os.path.join(app.config['UPLOAD_FOLDER'], name), 'r') as f:
            # Start the code cracking process in a separate thread
            # TODO: display tick messages for successful solving.
            hash_codes = f.read().split('\n')
            passwords = ["" for hash_code in hash_codes]
            found_passwords = [False for password in passwords]
            message = f'File "{name}" uploaded successfully! The cracking process has started.'
            cracking_thread = threading.Thread(target=code_cracking_task)
            cracking_thread.start()
            SOLVING = True
        return render_template('show_content.html', content=hash_codes, message=message)
    else:
        return 'File Not Found'


@app.route('/receive_password_status', methods=['POST'])
def receive_password_status():
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
    data = request.get_json()
    if data:
        hashed_password = data.get("hashed_password")
        hashed_password_index = data.get("hashed_password_index")
        if 0 <= hashed_password_index < len(hash_codes):
            # Check if the hashed password index is already solved
            is_solved = found_passwords[hashed_password_index]
            return {"already_solved": is_solved}

    return {"error": "Invalid data received"}, 400  # Bad Request status for invalid data


@app.route('/receive_password', methods=['POST'])
def receive_password():
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
    global hash_codes, found_passwords
    data = request.get_json()
    if data:
        solved_password = data.get("password")
        hashed_password = data.get("hashed_password")
        hashed_password_id = data.get("hashed_password_id")
        if 0 <= hashed_password_id < len(hash_codes):
            minion_id = data.get("minion_id")
            port = data.get("port")
            print(hash_codes[hashed_password_id] == hashed_password)
            print(hash_codes[hashed_password_id])
            print(hashed_password)
            print(validate_password(hashed_password, solved_password))
            if hash_codes[hashed_password_id] == hashed_password and\
                    validate_password(hashed_password, solved_password):
                found_passwords[hashed_password_id] = True
                passwords[hashed_password_id] = solved_password
                return "Password received successfully and matched, well done!"
            return "Password received successfully but didn't match."

    return "Invalid data received", 400  # Bad Request status for invalid data


@app.route('/get_updated_content')
def get_updated_content():
    global hash_codes
    return jsonify({'content': hash_codes})


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


if __name__ == '__main__':
    app.run(debug=True)
