# vtscanner - An Scanner App for Malicious Apps Detection

This app scans files, urls or hashes using api, the api used are from virustotal, Threatcrowd and Threatminer. But the main thing is virustotal. This application uses a Signature Based Detection approach

This app requires an api-key to scan because it uses the api from virustotal. If you don't have an api-key virustotal please register first

## Features

1. This application can scan a url or domain whether the site is dangerous or not
2. This application can scan a file based on the hash of the application scanned via     virustotal
3. This application can scan the hash to be scanned via virustotal

## How To Install 
 ```bash
 > git clone https://github.com/rasyidfox/vtscanner
 > cd vtscanner
 > pip install -r requirements.txt
 
 ```
## How To Usage
```bash
> python3 vtscanner.py -h
```
### How To Scan File
```bash
> python3 vtscanner.py -a <api-key> -f <file-name>
```

### How To Scan Hash

```bash
> python3 vtscanner.py -a <api-key> -hs <hash>
```

### How To Scan URL

```bash
> python3 vtscanner.py -a <api-key> -u <url>
```

#### Tested On : 

Windows 11 - Python 3.9.9
