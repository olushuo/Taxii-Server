- [cti-taxii-server 2.0](#cti-taxii-server-10)
  - [Description](#description)
  - [Usage](#usage)
    - [configuration](#configuration)
    - [Fake testing data](#fake-testing-data)
  - [Test](#test)
    - [Based on python 2.7](#based-on-python-27)
# cti-taxii-server 2.0 #

## Description ##
- Based on python 3.9 and medallion 3.0.0
- For testing the FDC's STIX feature.
- Supporting [STIX2.1](https://docs.oasis-open.org/cti/stix/v2.1/csprd01/stix-v2.1-csprd01.html)
- To test, please follow [TAXII2.1](https://docs.oasis-open.org/cti/taxii/v2.1/csprd02/taxii-v2.1-csprd02.html)

## Usage ##
If you are running it locally, for example Windows 11 desktop, you can directly run this following command
```bash
docker container run -d -p 444:444 -p 443:443 olushuo/cti-taxii-server:2.0
```
Otherwise, you mostly may need to run
```
docker container run -d -p 444:444 -p 443:443  -v <your data file folder>:/data olushuo/cti-taxii-server:2.0
```
- Taxii server is listening on port 444.
- Use port 443 to check if the Nginx is running(please add proper certificate into web browser).
- The TAXII service's IP is configured in the [`default_data_ssl.json`](#fake-testing-data).
- Since the nginx service is listening on both IPv4 and IPv6 address, the docker host need to enable IPv6 module.

### configuration ###
```bash
docker container run -d -p 444:444 -p 443:443  -v <your config file folder>:/conf olushuo/cti-taxii-server:2.0
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
*[defalut_data_ssl.json](https://github.com/olushuo/Taxxii-Server/blob/main/data/default_data_ssl.json)*
```bash
docker container run -d -p 444:444 -p 443:443  -v <your data file folder>:/data olushuo/cti-taxii-server:2.0
```
- Please modify the `/discovery` part, configure the proper IP here.
- Please keep "default_data.json" as the fake data file's name, otherwise please change the configuration file either.
![image](https://user-images.githubusercontent.com/13208409/152693962-284556fb-011e-4aa1-8860-836bf4857931.png)



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
*[test_ssl.py](https://github.com/olushuo/Taxxii-Server/blob/main/test_ssl.py)*

To test all test cases:
```
pytest -vs test_ssl.py
```
To test a particular case:
```
pytest -vs test_ssl.py::test_report_incident
```
