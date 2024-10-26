FROM python:3.12
WORKDIR /usr/local/app

# Install the application dependencies
COPY requirements.txt ./
RUN BUILD_LIB=1 pip install ssdeep
RUN pip install --no-cache-dir -r requirements.txt
RUN pip install pefile
RUN pip install Image
COPY ./src ./src

CMD [ "python", "src/Main.py"]
