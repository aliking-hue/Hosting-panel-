FROM python:3.9

# User setup
RUN useradd -m -u 1000 user
USER user
ENV PATH="/home/user/.local/bin:$PATH"

WORKDIR /home/user/app

# Copy files
COPY --chown=user . /home/user/app

# Install requirements
RUN pip install --no-cache-dir --upgrade -r requirements.txt

# Run the app (ensure app.py uses port 7860)
CMD ["python", "app.py"]
