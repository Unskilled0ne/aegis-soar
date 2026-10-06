FROM python:3.10-slim

WORKDIR /app

COPY requirements.txt .

RUN pip install --no-cache-dir -r requirements.txt

COPY . .

# Assuming it runs on port 8000 using uvicorn or similar
EXPOSE 8000

CMD ["python", "run_soar.py"]
