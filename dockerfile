# Step 1: Use an official Python image as the base
FROM python:3.10-slim

# Step 2: Set the working directory inside the container
WORKDIR /app

# Step 3: Copy the requirements.txt file into the container
COPY requirements.txt .

# Step 4: Install any dependencies from the requirements.txt
RUN pip install --no-cache-dir -r requirements.txt

# Step 5: Copy the current directory contents into the container
COPY . .

# Step 6: Set the command to run the application
CMD ["python", "app.py"]
