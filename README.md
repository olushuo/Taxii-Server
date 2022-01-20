- [cti-taxii-server 1.0](#cti-taxii-server-10)
  - [Description](#description)
  - [Usage](#usage)
    - [configuration](#configuration)
    - [Fake testing data](#fake-testing-data)
# cti-taxii-server 1.0 #

## Description ##
Based on python 3.9 and medallion 3.0.0

## Usage ##
```bash
docker container run -d -p 8080:8080 -p 80:80 olushuo/cti-taxii-server:1.0
```
- Taxii server is listening on port 8080.
- Use port 80 to check if the Nginx is sunning.

### configuration ###
```bash
docker container run -d -p 8080:8080 -p 80:80  -v <your config file folder>:/conf olushuo/cti-taxii-server:1.0
```
***A sample configuration file is as below***
```json
{
    "backend": {
        "module_class": "MemoryBackend",
        "module": "medallion.backends.memory_backend",
        "filename": "/data/default_data.json"
    },
    "users": {
        "admin": "fortinet",
        "fdc": "fortinet",
        "user": "fortinet"
    },
    "taxii": {
        "max_page_size": 100
    }
}
```
- We currently use an in-memory database for the testing environment.
- For a production environment, please replace the in-memory database with MongoDB.
- An in-memory database is good enough for testing, so please do not change the `backend` part unless you understand what you are doing.
- Please change the `users` part if you would like to change the credentials.

### Fake testing data ###
```bash
docker container run -d -p 8080:8080 -p 80:80  -v <your data file folder>:/conf olushuo/cti-taxii-server:1.0
```
- Please modify the `/discovery` part, configure the proper IP here.
- Please use "default_data.json" as the fake data file's name, otherwise please change the configuration file either.
***A sample data file is as below***
```json
{
    "/discovery": {
        "title": "Some TAXII Server",
        "description": "This TAXII Server contains a listing of",
        "contact": "string containing contact information",
        "default": "http://192.168.56.105:8080/trustgroup1/",
        "api_roots": [
            "http://192.168.56.105:8080/api1/",
            "http://192.168.56.105:8080/api2/",
            "http://192.168.56.105:8080/trustgroup1/"
        ]
    },
    "api1": {
        "information": {
            "title": "General STIX 2.1 Collections",
            "description": "A repo for general STIX data.",
            "versions": [
                "application/taxii+json;version=2.1"
            ],
            "max_content_length": 9765625
        },
        "status": [],
        "collections": []
    },
    "api2": {
        "inforver based on *[cti-taxii-server](https://github.com/oasis-open/cti-taxii-server)*. For testing FDC STIX feature.

