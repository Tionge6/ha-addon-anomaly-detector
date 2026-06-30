FROM python:3.11-alpine

# Install dependencies
RUN apk add --no-cache bash curl

# Install Python packages needed for detection
RUN pip install --no-cache-dir \
    requests \
    pandas \
    numpy

# Copy all detector files
COPY baseline.py  /app/baseline.py
COPY detector.py  /app/detector.py
COPY playbook.py  /app/playbook.py
COPY alerts.py    /app/alerts.py
COPY run.sh       /run.sh

RUN chmod +x /run.sh

WORKDIR /app

CMD ["/run.sh"]
