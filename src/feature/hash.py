#!/usr/bin/env python
"""
#
# Author: Necmettin Çarkacı
#
# E-mail: necmettin [ . ] carkaci [ @ ] gmail [ . ] com
#
# Usage :hash.py file
#   dataset : file or directory
"""

import hashlib
import ssdeep
import pefile

def getHashValues(filename, delimeter=','):
    """
        Calculate MD5, SHA-1, SHA-256, SHA-512 generic hash values
        calculate ssdeep fuzzy hashing (see : https://ssdeep-project.github.io/ssdeep/index.html)
        calculate imphash (see: https://www.fireeye.com/blog/threat-research/2014/01/tracking-malware-import-hashing.html)
        calculate Authedication PE hash; not implemented
        :param raw_data: Raw data
        :return: Hash values
        :rtype:dict (hash type : hash value)
    """

    with open(filename,'rb') as input_file:
        data = input_file.read()

    hash_values = {}
    hash_values['MD5']      = hashlib.md5(data).hexdigest()
    hash_values['SHA-1']    = hashlib.sha1(data).hexdigest()
    hash_values['SHA-256']  = hashlib.sha256(data).hexdigest()
    hash_values['SHA-512']  = hashlib.sha512(data).hexdigest()

    # Fuzzy Hash
    try:
        hash_values['ssdeep']   = ssdeep.hash(data) #:raises InternalError: If lib returns an internal error | raises TypeError: If buf is not String or Bytes
    except Exception as e:
        # FIXME : need for logging exception
        print("hash_values[ssdeep] error: " + str(e))
        hash_values['ssdeep'] = "None"
        pass
    # Import hash
    try:
        pe = pefile.PE(filename)
        hash_values['import-hash']  = pe.get_imphash()
    except Exception as e:
        print("hash_values[import-hash] error: " + str(e))
        hash_values['import-hash'] = "None"
        pass

    # Authedication hash
    # TODO : Implement this feature
    hash_values['authedication-hash'] = ''
    # URL : https://download.microsoft.com/download/9/c/5/9c5b2167-8017-4bae-9fde-d599bac8184a/Authenticode_PE.docx


    return hash_values
