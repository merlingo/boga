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
import hashlib

def getImportTable(filename, delimeter=','):
    """
        Create windows import function call frequency.
        Get import function list from PE header.
        It merge entry.dll and import_function name and create a hash value.
        And search usage number of the import function in disaasembled file,
        create usage frequency disct.  Return this dictionary key.

    :param filename:
    :return: api call frequency
    :rtype:dict (api name, call frequency)
    """
    pe = pefile.PE(filename, fast_load=True)
    pe.parse_data_directories()

    import_function_dict = {}

    try:
        for entry in pe.DIRECTORY_ENTRY_IMPORT:
            for import_function in entry.imports:
                if import_function.name is not None:

                    imp_function = str(entry.dll).encode('utf-8')+'->'+str(import_function.name).encode('utf-8')

                    # If you want use static function list use this code piece
                    """
                    imp_func_hash_value = hashlib.md5(str((entry.dll, import_function.name)).encode('utf-8')).hexdigest()
                    imp_func_hash_id    = (int(imp_func_hash_value, 16) % 256)

                    if imp_func_hash_id in import_function_dict.keys():
                        import_function_dict[imp_func_hash_id] += 1
                    else:
                        import_function_dict[imp_func_hash_id]  = 1
                    """

                    if imp_function in import_function_dict.keys():
                        import_function_dict[imp_function] += 1
                    else:
                        import_function_dict[imp_function]  = 1

        return import_function_dict

    except Exception as err:

        return None

