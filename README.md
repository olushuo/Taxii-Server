- [cti-taxii-server 1.0](#cti-taxii-server-10)
  - [Description](#description)
  - [Usage](#usage)
    - [configuration](#configuration)
    - [Fake testing data](#fake-testing-data)
  - [- Please use "default_data.json" as the fake data file's name, otherwise please change the configuration file either.</br>](#--please-use-default_datajson-as-the-fake-data-files-name-otherwise-please-change-the-configuration-file-eitherbr)
  - [Test](#test)
    - [Based on python 2.7](#based-on-python-27)
# cti-taxii-server 1.0 #

## Description ##
Based on python 3.9 and medallion 3.0.0

## Usage ##
```bash
docker container run -d -p 8080:8080 -p 80:80 olushuo/cti-taxii-server:1.0
```
- Taxii server is listening on port 8080.
- Use port 80 to check if the Nginx is running.

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
docker container run -d -p 8080:8080 -p 80:80  -v <your data file folder>:/data olushuo/cti-taxii-server:1.0
```
- Please modify the `/discovery` part, configure the proper IP here.
- Please use "default_data.json" as the fake data file's name, otherwise please change the configuration file either.</br>
---
***A sample data file --->***
*[defalut_data.json](https://github.com/olushuo/Taxxii-Server/blob/main/data/default_data.json)*

## Test ##
### Based on python 2.7 ###
```bash
conda create -n taxii-test python=2.7
conda activate taxii-test
```

