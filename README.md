File Store App
---
Designed to securely store, read, update, and delete files from GCP cloud-storage and their metadata and user details are stored in MySQL database. The application can easily be deploy on-premise or on the cloud. As the application is containerized it makes it much easier.

Running the application
---
Create a `.env` file and provide the required evironmental variables.
Following is a sample `.env` file
```
DB_URI=mysql+pymysql://<username>:<password>@<database-host>:<database-port>/<database-name> # Database URI
PORT=8081 # Port for application
SECRET_KEY=<secret-key> # Random key would be used as the key for session
GOOGLE_APPLICATION_CREDENTIALS=<path> # Path to GCP credential files
BUCKET_NAME=<bucket-name>
```
Update the above sample as required.
