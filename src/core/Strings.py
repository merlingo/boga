#!/usr/bin/env python
"""
    Extract Unicode and Ascii string sequence from executable file.
#
# Author: Mert NAR
#
# E-mail: mrt [ . ] narr [ @ ] gmail [ . ] com
#

"""

import re, os
from . import errors
# TODO : is exist url, is exist domain, domain length, subdomain length, domain contain number, sub domain contain number
# domain contain unresolve char, subdomain contain unresolve char
import fileutil
REGEX_STANDARD = '[\x09\x20-\x7E]'

#  Imme Emosol  regex : https://gist.github.com/imme-emosol/731338/810d83626a6d79f40a251f250ed4625cac0e731f
# Other regex : https://mathiasbynens.be/demo/url-regex
URL_REGEX = r'^(?:(?:https?|ftp)://)(?:\S+(?::\S*)?@)?(?:(?:[1-9]\d?|1\d\d|2[01]\d|22[0-3])(?:\.(?:1?\d{1,2}|2[0-4]\d|25[0-5])){2}(?:\.(?:[1-9]\d?|1\d\d|2[0-4]\d|25[0-4]))|(?:(?:[a-z\u00a1-\uffff0-9]+-?)*[a-z\u00a1-\uffff0-9]+)(?:\.(?:[a-z\u00a1-\uffff0-9]+-?)*[a-z\u00a1-\uffff0-9]+)*(?:\.(?:[a-z\u00a1-\uffff]{2,})))(?::\d{2,5})?(?:/[^\s]*)?$'

def extractStringsASCII(data):
    regex = REGEX_STANDARD + '{%d,}'
    return re.findall(regex % 4, data)

def extractStringsUNICODE(data):
    regex = '((' + REGEX_STANDARD + '\x00){%d,})'
    return [foundunicodestring.replace('\x00', '') for foundunicodestring, dummy in re.findall(regex % 4, data)]

def extractStrings(data):

    return extractStringsASCII(data) + extractStringsUNICODE(data)

def urlandDomainList(filename):
    """
        Check url : https://mathiasbynens.be/demo/url-regex
        :param filename:
        :return:
    """
    with open(filename,'r', encoding = "ISO-8859-1") as input_file:
        data = input_file.read()

    url_list = re.findall(URL_REGEX, data)
    delimeter = '\n'
    content = delimeter.join(url_list)
    return content

def extractAsText(string_list):
    print("extracting string in text format")
    delimeter = '\n'
    content = delimeter.join(string_list)
    #write content in text file at the directory of out_dir
    return content


def extractAsSeq(string_list):
    print("extracting string in sequence format")
    delimeter = ','
    content = delimeter.join(string_list)
    return content


def getStrings(filename, out_ext, out_dir):

    
    with open(filename,'r', encoding = "ISO-8859-1") as input_file:
        data = input_file.read()

        string_list = extractStrings(data)
        content =""
        if out_ext == "text":
            content = extractAsText(string_list)
        elif out_ext == "seq":
            content= extractAsSeq(string_list)
        elif out_ext == "url":
            content = urlandDomainList(filename)
        elif out_ext == "vec":
            #extractAsVec(string_list,out_dir)
            raise errors.UnexecutableFormatError(out_ext)
        elif out_ext == "dot":
            #extractAsDot(string_list,out_dir)
            raise errors.UnexecutableFormatError(out_ext)
        else:
            raise errors.UnsupportedFormatSelectionError(out_ext)
        
        #write content into file and directory
        fileutil.writeIntoFile(filename,out_dir,out_ext,content)

    #return delimeter.join(string_list)

