#!/usr/bin/env python
"""
#
# Author: Necmettin Çarkacı
#
# E-mail: necmettin [ . ] carkaci [ @ ] gmail [ . ] com
#
# Usage :opcode.py file
#   dataset : file or directory
"""

import pefile
import subprocess

def getWinApiListFrequency(filename, delimeter=','):
    """
        Create windows api function call frequency.
        Get api list from PE header. And search usage in disaasembled file,
        create usage frequency disct.

    :param filename:
    :return: api call frequency
    :rtype:dict (api name, call frequency)
    """
    try:

        api_list = {}
        pe = pefile.PE(filename)

        for entry in pe.DIRECTORY_ENTRY_IMPORT:
            for import_function in entry.imports:
                if import_function.name is not None:
                    api_list[hex(import_function.address)] = import_function.name.decode("utf-8")

        api_frequency = {}
        disas = subprocess.check_output(["objdump", "-d", "-M", "intel", filename])

        for line in disas.decode("utf-8").split('\n'):

            if "call" in line and "ds:" in line:

                address = line.split("ds:")[1]

                if address in api_list:

                    function_name = api_list[address]

                    if function_name in api_frequency.keys():
                        api_frequency[function_name] += 1
                    else:
                        api_frequency[function_name] = 1

        return api_frequency

    except Exception as err:

        return None
