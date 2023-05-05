FROM python:3.11

WORKDIR /app

COPY . /app/
RUN pip install --no-cache-dir -r requirements.txt

EXPOSE 5001

CMD ["python", "app.py", "--port", "5001"]
