- [cti-taxii-server 1.0](#cti-taxii-server-10)
  - [Description](#description)
  - [Usage](#usage)
    - [configuration](#configuration)
    - [Fake testing data](#fake-testing-data)
  - [Test](#test)
    - [Based on python 2.7](#based-on-python-27)
# cti-taxii-server 1.0 #

## Description ##
- Based on python 3.9 and medallion 3.0.0
- For testing the FDC's STIX feature.
- Supporting [STIX2.1](https://docs.oasis-open.org/cti/stix/v2.1/csprd01/stix-v2.1-csprd01.html)
- To test, please follow [TAXII2.1](https://docs.oasis-open.org/cti/taxii/v2.1/csprd02/taxii-v2.1-csprd02.html)

## Usage ##
If you are running it in VritualBox and the VM's ip is `192.168.56.105`, you can directly run this following command
```bash
docker container run -d -p 8080:8080 -p 81:80 olushuo/cti-taxii-server:1.0
```
Otherwise, you mostly may need to run
```
docker container run -d -p 8080:8080 -p 81:80  -v <your data file folder>:/data olushuo/cti-taxii-server:1.0
```
- Taxii server is listening on port 8080.
- Use port 81 to check if the Nginx is running.
- The TAXII service's IP is configured in the [`default_data.json`](#fake-testing-data).
- Since the nginx service is listening on both IPv4 and IPv6 address, the docker host need to enable IPv6 module.

### configuration ###
```bash
docker container run -d -p 8080:8080 -p 81:80  -v <your config file folder>:/conf olushuo/cti-taxii-server:1.0
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
***A sample data file --->***
*[defalut_data.json](https://github.com/olushuo/Taxxii-Server/blob/main/data/default_data.json)*
```bash
docker container run -d -p 8080:8080 -p 81:80  -v <your data file folder>:/data olushuo/cti-taxii-server:1.0
```
- Please modify the `/discovery` part, configure the proper IP here.
- Please keep "default_data.json" as the fake data file's name, otherwise please change the configuration file either.
![image](https://user-images.githubusercontent.com/13208409/150575431-ea753a35-1e5d-458e-a025-599cab214db9.png)


## Test ##
### Based on python 2.7 ###
```bash
conda create -n taxii-test python=2.7
conda activate taxii-test
pip install --upgrade pip
pip install taxii2-client
pip install stix2
pip install pytest
```
***A sample test file --->***
*[test.py](https://github.com/olushuo/Taxxii-Server/blob/main/test.py)*

To test all test cases:
```
pytest -vs test.py
```
To test a particular case:
```
pytest -vs test.py::test_report_incident
```
