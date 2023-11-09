# pentera Password Cracker

## Overview

The Password Cracker project is a distributed system that cracks MD5 hashed passwords.  
It involves a master server and multiple minions servers.  
The master server distributes tasks to minions for parallel processing to find the original passwords corresponding to the provided hashed passwords.
The minions, acting as workers in the distributed system, perform calculations to tasks they receive from the master.

## Technologies Used

- Python
- Flask
- Werkzeug
- Requests
- hashlib
- Threading
- multiprocessing

## File Structure

- `master.py`: Main Flask application for the master server.
- `taskQueue.py`: Task queue utility for task management.
- `minion.py`: Main Flask application for the minion server.
- `master.py`: Main Flask application for the master server.
- `requirements.txt`: The requirements needed to run the servers.


## Installation

1. Clone the repository.
2. Install the required Python packages by executing the following command in your terminal:
    ```bash
    pip install -r requirements.txt
    ```
   Ensure you have an active Python environment set up.

3. Configure the settings in the designated configuration file (to be provided in the project).
4. Run the Flask applications using `python master.py`.


## Usage

1. Run the Master servers.  
2. Run the Minions servers.  
3. Access the master server endpoint (`/`).  
4. Upload a file containing MD5 hashed passwords in this format 05X-XXXXXXX.  
5. The master server will initiate the code cracking process and distribute tasks to the minions.  
6. Minions process tasks to find the original passwords.  
7. Monitor the progress shown on the screen.  
8. Extract the output.txt file containing the hashed passwords.  


## API Endpoints

### Master Server

- `/uploads/<name>` - Serve the uploaded file and commence the code cracking process.
  - **Data Input**:
    - Endpoint expects the filename of the uploaded file in the URL path.

- `/status` - Check the status of a hashed password by its index.
  - **Data Input**:
    - JSON Structure:
      - `"hashed_password"` (string): The hashed password string.
      - `"hashed_password_index"` (integer): Index of the hashed password.

- `/content` - Retrieve the updated content of the hash codes and their cracking status.
  - **Data Input**:
    - No data input required.

- `/minion` - Add a new minion address.
  - **Data Input**:
    - JSON Structure:
      - `"new_address"` (string): Address of the new minion server.

### Minion Server

- `/task` - Receive tasks from the master for processing.
  - **Data Input**:
    - JSON Structure representing a task. This should match the format detailed in the minion documentation.

- `/password` - Send solved passwords to the master.
  - **Data Input**:
    - JSON Structure:
      - `"password"` (string): The solved password.
      - `"hashed_password"` (string): The hashed password string.
      - `"hashed_password_id"` (integer): ID of the hashed password.
      - `"minion_id"` (string): ID or Address of the minion.
      - `"port"` (string): Minion port.

- `/status` - Check if a hashed word is already solved.
  - **Data Input**:
    - JSON Structure:
      - `"hashed_password_index"` (integer): Index of the hashed password.


## Workflow

The master server receives the hashed passwords, generates tasks for minions, and distributes these tasks for parallel processing.  
Minions work on the received tasks to crack the passwords. Once a password is found, the minions update the master server with the solution.

## Future Improvements

- Implement additional security features.
- Optimize task distribution for better load balancing.
- Enhance error handling and reporting.
- Implement data recovery when crashing at master.


## License

This project is under the [MIT License].
