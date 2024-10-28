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

import re
import datetime
import pefile
import peutils

def entropy_check(pe):
    """
        File is possibly packed
    :return:
    """
    anomaly_dict = {}
    pack = peutils.is_probably_packed(pe)
    if pack == 1:
        anomaly_dict["fileIsPacked"] = 1
    else:
        anomaly_dict["fileIsPacked"] = 0

    return anomaly_dict


def illegal_size_of_raw_data(pe):
    # SizeOfRawData Check..
    # some times size of raw data value is used to crash some debugging tools.
    # The Size Of Raw data is valued illegal! Binary might crash your disassembler/debugger

    anomaly_dict = {}

    number_of_section = len(pe.sections)
    for index in range(number_of_section - 1):

        next_pointer = pe.sections[index].SizeOfRawData + pe.sections[index].PointerToRawData
        curr_pointer = pe.sections[index + 1].PointerToRawData

        if next_pointer != curr_pointer:
            anomaly_dict["illegalSizeOfRawData"] = 1
            break
    anomaly_dict["illegalSizeOfRawData"] = 0

    return anomaly_dict


def non_ascii_section_name(pe):
    # Non-Ascii or empty section name check
    # Non-ascii or empty section names detected

    anomaly_dict = {}
    for section in pe.sections:
        if not re.match("^[.A-Za-z][a-zA-Z]+", str(section.Name)):
            anomaly_dict["non-asciiSectionName"] = 1
            break

    anomaly_dict["non-asciiSectionName"] = 0
    return anomaly_dict


def size_optional_header(pe):
    # Size of optional header check
    # Illegal size of optional Header

    anomaly_dict = {}
    if pe.FILE_HEADER.SizeOfOptionalHeader != 224:
        anomaly_dict["illegalSizeOptHeader"] = 1

    else:
        anomaly_dict["illegalSizeOptHeader"] = 0

    return anomaly_dict


def zero_checksum(pe):
    # Zero checksum check
    # Header Checksum is zero!

    anomaly_dict = {}

    if pe.OPTIONAL_HEADER.CheckSum == 0:
        anomaly_dict["headerChecksumZero"] = 1
    else:
        anomaly_dict["headerChecksumZero"] = 0

    return anomaly_dict


def entropy_point_check(pe):
    # Entry point check
    # Enrty point is outside the 1st(.code) section! Binary is possibly packed

    anomaly_dict = {}

    enaddr = pe.OPTIONAL_HEADER.AddressOfEntryPoint
    vbsecaddr = pe.sections[0].VirtualAddress
    ensecaddr = pe.sections[0].Misc_VirtualSize
    entaddr = vbsecaddr + ensecaddr

    if enaddr > entaddr:
        anomaly_dict['EnrtyPointOutside'] = 1
    else:
        anomaly_dict['EnrtyPointOutside'] = 0

    return anomaly_dict


def number_of_rva_size(pe):
    # Numeber of directories check
    # Optional Header NumberOfRvaAndSizes field is valued illegal

    anomaly_dict = {}

    if pe.OPTIONAL_HEADER.NumberOfRvaAndSizes != 16:
        anomaly_dict["NumberOfRvaAndSizes"] = 1

    else:
        anomaly_dict["NumberOfRvaAndSizes"] = 0

    return anomaly_dict


def loader_flag(pe):
    # Loader flags check
    # Optional Header LoaderFlags field is valued illegal

    anomaly_dict = {}

    if pe.OPTIONAL_HEADER.LoaderFlags != 0:
        anomaly_dict["LoaderFlagsIlegal"] = 1
    else:
        anomaly_dict["LoaderFlagsIlegal"] = 0

    return anomaly_dict


def TSL(pe):
    # TLS (Thread Local Storage) callback function check
    # TLS callback functions array detected

    anomaly_dict = {}

    if hasattr(pe, "DIRECTORY_ENTRY_TLS"):
        anomaly_dict["callbackFunction"] = 1
    else:
        anomaly_dict["callbackFunction"] = 0

    return anomaly_dict


def time_date_future(pe):
    anomaly_dict = {}

    creation_timestamp = pe.FILE_HEADER.TimeDateStamp
    creation_year = _file_creation_year(creation_timestamp)
    currentYear = datetime.date.today().year

    if creation_year > currentYear:
        anomaly_dict["timeDateInFuture"] = 1
    else:
        anomaly_dict["timeDateInFuture"] = 0

    return anomaly_dict


def time_date_too_low(pe):
    """
    Check file creation time old or not
    :return:
    """

    anomaly_dict = {}

    creation_timestamp = pe.FILE_HEADER.TimeDateStamp
    creation = _file_creation_year(creation_timestamp)

    if creation < 1980:
        anomaly_dict["timeDateTooLow"] = 1
    else:
        anomaly_dict["timeDateTooLow"] = 0

    return anomaly_dict


def unordenerySectionName(pe):
    anomaly_dict = {}

    benign_sections = set(['.text', '.data', '.rdata', '.idata', '.edata', '.rsrc', '.bss', '.crt', '.tls'])

    for section in pe.sections:

        if str(section.Name).split('\x00')[0] not in benign_sections:
            anomaly_dict["unorderedSectionName"] = 1

    anomaly_dict["unorderedSectionName"] = 0

    return anomaly_dict


def unordenerySectionNumber(pe):
    anomaly_dict = {}

    benign_sections = set(['.text', '.data', '.rdata', '.idata', '.edata', '.rsrc', '.bss', '.crt', '.tls'])
    unordered_section_number = 0

    for section in pe.sections:

        if str(section.Name).split('\x00')[0] not in benign_sections:
            unordered_section_number += 1

    anomaly_dict["unorderedSectionNumber"] = unordered_section_number

    return anomaly_dict


def _file_creation_year(creation_timestamp):
    """
        Find file creation year
        :param creation_timestamp : File creation timestamp
        :type creation_timestamp: second
    :return:
    """
    return 1970 + ((int(creation_timestamp) / 86400) / 365)


def getAnomalies(filename, delimeter=','):
    anomaly_dict = {}
    try:
        pe = pefile.PE(filename)
    except Exception as e:
        print("anomalies.getAnomalies: pe file can not be extracted - " + str(e))
        return anomaly_dict  # no key attentments which doesnt use pe file here. so if there is not pe file then empty dict is returned

    anomaly_dict.update(entropy_check(pe))
    anomaly_dict.update(entropy_point_check(pe))
    anomaly_dict.update(illegal_size_of_raw_data(pe))
    anomaly_dict.update(loader_flag(pe))
    anomaly_dict.update(non_ascii_section_name(pe))
    anomaly_dict.update(number_of_rva_size(pe))
    anomaly_dict.update(size_optional_header(pe))
    anomaly_dict.update(time_date_future(pe))
    anomaly_dict.update(time_date_too_low(pe))
    anomaly_dict.update(TSL(pe))
    anomaly_dict.update(unordenerySectionName(pe))
    anomaly_dict.update(unordenerySectionNumber(pe))
    anomaly_dict.update(zero_checksum(pe))

    return anomaly_dict
