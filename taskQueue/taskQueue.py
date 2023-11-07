class TaskQueue:
    def __init__(self):
        self.queue = []  # A list to store tasks

    def add_task(self, task_id, task_data):
        """Add a task to the queue."""
        self.queue.append({"id": task_id, "data": task_data})

    def remove_task_by_id(self, task_id):
        """Remove a task from the queue based on its ID."""
        for task in self.queue:
            if task["id"] == task_id:
                self.queue.remove(task)
                return task  # Returning the removed task
        return None  # Return None if the task ID is not found

    def get_first_task(self):
        """Get the first task from the queue and update the queue."""
        if self.queue:
            first_task = self.queue.pop(0)  # Remove the first task from the queue
            self.queue.append(first_task)  # Append the first task to the end of the queue
            return first_task
        return None  # Return None if the queue is empty

    def display(self):
        """Display the current tasks in the queue."""
        print("Tasks in the queue:")
        for task in self.queue:
            print(task)

