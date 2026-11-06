# 1. Use the official Python 3.13 slim image (lighter than the full image)
FROM python:3.13-slim

# 2. Set environment variables
# Prevents Python from writing .pyc files
ENV PYTHONDONTWRITEBYTECODE=1
# Prevents Python from buffering stdout and stderr (crucial for seeing logs immediately)
ENV PYTHONUNBUFFERED=1

# 3. Set the working directory inside the container
WORKDIR /app

# 4. Install dependencies
# 🔗 Remember Section 03, §3.4: We use the pinned requirements.txt
COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt

# 5. Copy the rest of the project code
COPY . .

# 6. Expose port 8000
EXPOSE 8000

# 7. Run the Django development server
# 🔗 Remember Master Prompt §16: Inside Docker, we must bind to 0.0.0.0, not 127.0.0.1
CMD ["python", "manage.py", "runserver", "0.0.0.0:8000"]
