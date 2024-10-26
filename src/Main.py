import hashlib
import csv
import os, math, array
import requests

vt_api ="f2dda88f5dd8c27aa2d58752e57bdcaec55273299138d399c69c561542a38722"
def hashing(file):
    in_file = open(file, "rb") # opening for [r]eading as [b]inary
    data = in_file.read() # if you only wanted to read 512 bytes, do .read(512)
    in_file.close() 
    result = hashlib.md5(data)
    return result.hexdigest()

def get_entropy(file):
    """
        Calculate Shannon entropy
        Entropy (x) = -p(x)*log(p(x))

    :param raw_data: Binary digits
    :return: entropy value
    :rtype:float
    """
    in_file = open(file, "rb") # opening for [r]eading as [b]inary
    raw_data = in_file.read() # if you only wanted to read 512 bytes, do .read(512)
    if len(raw_data) == 0:
        return 0.0
    occurences = array.array('L', [0] * 256)
    for x in raw_data:
        occurences[x if isinstance(x, int) else ord(x)] += 1

    entropy = 0
    for x in occurences:
        if x:
            p_x = float(x) / len(raw_data)
            entropy -= p_x * math.log(p_x, 2)

    return entropy

def size(file):
    file_stats = os.stat(file)
    return file_stats.st_size

def vt_score(file):
    resp = getVirustotalReport(file,vt_api)
    return resp["positives"]

main_functions = [size,hashing,get_entropy,vt_score]
headers=["filename", "size", "hashing","entropy","vt_score"]
def run(dataset,outfile):
    with open(outfile, 'w', newline='') as csvfile:
        writer = csv.writer(csvfile, delimiter=',')
        writer.writerow(headers)
        for file in dataset:
            print(file)
            row = []
            row.append(file)
            row.extend([f(file) for f in main_functions])
            writer.writerow(row)

    print(row)




def getVirustotalReport(filename, API_KEY,isFile=1, proxy=None):

      headers = {
      "Accept-Encoding": "gzip, deflate",
      "User-Agent" : "gzip,  My Python requests library example client or username"
      }
      if(isFile):
        with open(filename, 'rb') as input_file:
            data = input_file.read()
            file_hash_value = hashlib.md5(data).hexdigest()

      else:
          file_hash_value = filename
      #print(file_hash_value)
      params = {'apikey': API_KEY, 'resource':file_hash_value}
      if(proxy is None):
        response = requests.get('https://www.virustotal.com/vtapi/v2/file/report',params=params, headers=headers)
      else:
        response = requests.get('https://www.virustotal.com/vtapi/v2/file/report', params=params, headers=headers,proxies=proxy)

      #FIXME: if result none there can be problem check this
      json_response = response.json()
      return json_response