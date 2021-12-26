import vt
import argparse
import os
import hashlib
import requests


def clear():
  if os.name == 'nt':
    os.system('cls')
  else:
    os.system('clear')

clear()

print ("""

██╗░░░██╗████████╗░██████╗░█████╗░░█████╗░███╗░░██╗███╗░░██╗███████╗██████╗░
██║░░░██║╚══██╔══╝██╔════╝██╔══██╗██╔══██╗████╗░██║████╗░██║██╔════╝██╔══██╗
╚██╗░██╔╝░░░██║░░░╚█████╗░██║░░╚═╝███████║██╔██╗██║██╔██╗██║█████╗░░██████╔╝
░╚████╔╝░░░░██║░░░░╚═══██╗██║░░██╗██╔══██║██║╚████║██║╚████║██╔══╝░░██╔══██╗
░░╚██╔╝░░░░░██║░░░██████╔╝╚█████╔╝██║░░██║██║░╚███║██║░╚███║███████╗██║░░██║
░░░╚═╝░░░░░░╚═╝░░░╚═════╝░░╚════╝░╚═╝░░╚═╝╚═╝░░╚══╝╚═╝░░╚══╝╚══════╝╚═╝░░╚═╝
by : Rasyidfox

""")

def get_options():
    parser = argparse.ArgumentParser(description='Cekk')
    parser.add_argument("-a", "--api-key", dest="apikey", required=True, help="It's a VirusTotal API Key")
    parser.add_argument("-f", "--files", dest="file", help="File path query", type=argparse.FileType('rb'))
    parser.add_argument("-u", "--url", dest="url", help="It's URL you want to scan")
    parser.add_argument("-hs", "--hashes", dest="hashes", help="Hash of file")
    return parser.parse_args()

def scan_url():
    parse = get_options()

    with vt.Client(parse.apikey) as client:
        try:
            url_id = vt.url_id(parse.url)
            url = client.get_object("/urls/{}", url_id)
            url.last_analysis_stats
            print(f"Result Scan {parse.url}: \n")
            if url.last_analysis_stats["malicious"] == 0:
                print(f"This URL {parse.url} not contain Malicious!\n")
            else:
                print(f"This URL P{parse.url} contain Malicious!\n")
            for key in url.last_analysis_stats:
                print("[+]", key, ":", url.last_analysis_stats[key])
        except:
            print ("URL Unknown!")
        
def scan_hash():
    parse = get_options()
    with vt.Client(parse.apikey) as client:
        hash_id = parse.hashes
        id_hash = parse.hashes
        hash = client.get_object("/files/{}", hash_id)
        hash.last_analysis_stats
        print(f"Result for scanning hash {hash_id}\n")
        if hash.last_analysis_stats["malicious"] == 0:
            print ("This Hash not contain Malware!")
        else:
            print ("This Hash contain Malware!")
        for key in hash.last_analysis_stats:
            print("[+]", key, ":", hash.last_analysis_stats[key])
            
    print("\n")
    print("Threat Crowd Scans Hash")
    url = f"https://www.threatcrowd.org/searchApi/v2/file/report/?resource={id_hash}\n"
    response = requests.get(url)

    if response.status_code == requests.codes.ok:
        hasil = response.json()
        
        try:
            o = hasil['scans']
            for i in range(len(o)):
                print(i, ":" , o[i])
            print("Domains :", hasil["domains"])
        except:
            print ("This Hash not Contain Malware!")

    print("\n")
    print("Threat Miner Scans File")
    url = f"https://api.threatminer.org/v2/sample.php?q={id_hash}&rt=6"
    response = requests.get(url)

    if response.status_code == requests.codes.ok:   
        try:
            hasil = response.json()
            o = hasil['results'][0]['av_detections']
            for i in range(len(o)):
                print(f"{i}. {o[i]}")
        except:
            print("This hash not contain Malware!")
    
def scan_file():
    parse = get_options()
    name = parse.file
    file_hash = hashlib.sha256(parse.file.read()).hexdigest()
    with vt.Client(parse.apikey) as client:
        hash = client.get_object("/files/{}", file_hash)
        hash.last_analysis_stats
        print(f"Result for scanning hash {name}\n")
        print(f"Hash : {file_hash}\n")
        if hash.last_analysis_stats["malicious"] == 0:
            print ("This Files not contain Malware!")
        else:
            print ("This Files contain Malware!")
        for key in hash.last_analysis_stats:
            print("[+]", key, ":", hash.last_analysis_stats[key])

    print("\n")
    print("Threat Crowd Scans File")
    url = f"https://www.threatcrowd.org/searchApi/v2/file/report/?resource={file_hash}\n"
    response = requests.get(url)

    if response.status_code == requests.codes.ok:
        hasil = response.json()
        
        try:
            o = hasil['scans']
            for i in range(len(o)):
                print(i, ":" , o[i])
            print("Domains :", hasil["domains"])
        except:
            print ("This Files not Contain Malware!")
    
    print("\n")
    print("Threat Miner Scans File")
    url = f"https://api.threatminer.org/v2/sample.php?q={file_hash}&rt=6"
    response = requests.get(url)

    if response.status_code == requests.codes.ok:   
        try:
            hasil = response.json()
            o = hasil['results'][0]['av_detections']
            for i in range(len(o)):
                print(f"{i}. {o[i]}")
        except:
            print("This hash not contain Malware!")

def main():
    parse = get_options()

    if parse.apikey and parse.url:
        scan_url()
    elif parse.apikey and parse.hashes:
        scan_hash()
    elif parse.apikey and parse.file:
        scan_file()
    else:
        print ("No Option Specified.")

if __name__ == "__main__":
  main()