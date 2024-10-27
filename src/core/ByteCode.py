#!/usr/bin/env python
"""
    Extract hexdump from executable file.
#
# Author: Necmettin Çarkacı
#
# E-mail: necmettin [ . ] carkaci [ @ ] gmail [ . ] com
#
# Usage :opcode.py file
#   dataset : file or directory
"""
from core import Disassembler


def getByteCode(filename, delimeter=',', bits='32bit'):
    """
        Extract hex code from executable file.
        :param filename : Executable file path
        :type filename: str
        :param bits : File platform 16, 32 or 64.
        :type bits : str [16bit, 32bit, 64bit] (default:32bit)
        :return: hexcode sequence
        :rtype:str
    """
    iterable = Disassembler.diassemble(filename,bits)

    hexcode = ''
    for (offset, size, instruction, hexdump) in iterable:

        # To avoid TypeError: a bytes-like object is required, not 'str'
        hexdump = hexdump.decode().replace('\n','')
        hexcode += hexdump

    return hexcode


