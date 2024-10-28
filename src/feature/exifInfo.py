#!/usr/bin/env python
"""
    Extract anomalies from executable file.
#
# Author: Necmettin Çarkacı
#
# E-mail: necmettin [ . ] carkaci [ @ ] gmail [ . ] com

# URL : https://github.com/cysinfo/Exescan/blob/master/exescan.py
# URL : https://github.com/urwithajit9/ClaMP/blob/master/scripts/integrated_features_extraction.py
#
# Usage :opcode.py file
#   dataset : file or directory
"""

import subprocess

NONESSENTIAL_INFO_LIST = ['Directory', 'ExifTool Version Number', 'File Name', 'File Permissions']

def getExifInfo(filename, delimeter=','):
    """
        Use linux exiftool command to extract exif info

        URL : https://www.sno.phy.queensu.ca/~phil/exiftool/

        :param filename: Binary filename
        :type filename : str
        :return: Exif information
        :rtype:dict (exif info : value)

    """
    exif_info = {}
    try:
        # exiftool parameters :
        # -f Force printing of all specified tags
        # -G Print group name for each tag
        # -j Export/import tags in JSON format
        # -csv Export/import tags in CSV format
        # -sort Sort output alphabetically

        command_line = ['exiftool','-f', '-sort', filename]
        result = subprocess.check_output(command_line)


        if result:
            # convert bytes to string
            result = result.decode('utf-8')

            info_list = result.split('\n')

            for info in info_list:

                if info != '':

                    info = info.split(': ')

                    if info[0].rstrip() not in NONESSENTIAL_INFO_LIST:
                        exif_info[info[0].rstrip()] = info[1]


    except Exception as err:
        print("Error occured while exract exif information - #empty dictionary returned \n"+filename+str(err))
        # FIXME: Log error here

    return exif_info
