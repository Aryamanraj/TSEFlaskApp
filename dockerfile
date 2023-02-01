# Use an official Python runtime as the parent image
FROM python:3.8-slim-buster

# Set the working directory to /app
WORKDIR /code

# Copy the current directory contents into the container at /app
COPY . .

# Install the required packages
RUN pip install --no-cache-dir -r requirements.txt


# Set environment variables
ENV FLASK_APP=app.py
ENV FLASK_RUN_HOST=0.0.0.0


# Expose port 5000 for Flask to listen on
EXPOSE 6117

# Define the command to run the application
CMD ["python", "-u", "./app.py"]
