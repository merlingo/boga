#!/usr/bin/env python
"""
    Extract Unicode and Ascii string sequence from executable file.
#
# Author: Mert NAR
#
# E-mail: mrt [ . ] narr [ @ ] gmail [ . ] com
#

"""

import re

# TODO : is exist url, is exist domain, domain length, subdomain length, domain contain number, sub domain contain number
# domain contain unresolve char, subdomain contain unresolve char

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
    return url_list


def getStrings(filename, delimeter='\n'):

    with open(filename,'r', encoding = "ISO-8859-1") as input_file:
        data = input_file.read()

    string_list = extractStrings(data)
    return delimeter.join(string_list)