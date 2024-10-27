#!/usr/bin/env python
"""
    Extract Operational Code (Opcode) sequence from executable file.
#
# Author: Necmettin Çarkacı
#
# E-mail: necmettin [ . ] carkaci [ @ ] gmail [ . ] com
#
# Usage :opcode.py file
#   dataset : file or directory
"""


from core import Disassembler


def getOpcode(filename, delimeter='\n', bits='32bit'):

    iterable = Disassembler.diassemble(filename,bits)



    opcode_code = ''
    for (offset, size, instruction, hexdump) in iterable:
        # To avoid TypeError: a bytes-like object is required, not 'str'
        print(instruction)
        #instruction = instruction.decode()

        opcode = instruction.split(" ")[0]  # get opcode
        opcode_code += opcode+delimeter

    return opcode_code

def getOpcodeList(filename, bits='32bit'):

    iterable = Disassembler.diassemble(filename,bits)

    opcode_code_list = []
    for (offset, size, instruction, hexdump) in iterable:

        # To avoid TypeError: a bytes-like object is required, not 'str'
        instruction = instruction.decode()

        opcode = instruction.split(" ")[0]  # get opcode
        opcode_code_list.append(opcode)

    return opcode_code_list
def getOpcodeFromFile(filename,delimiter=","):

    with open(filename,"r") as file:
        opcodes = file.read()
    return opcodes.split(delimiter)
def getOpcodeFrequency(filename, bits='32bit'):

    iterable = Disassembler.diassemble(filename,bits)

    opcode_frequency_dict = {}
    for (offset, size, instruction, hexdump) in iterable:

        # To avoid TypeError: a bytes-like object is required, not 'str'
        instruction = instruction.decode()


        opcode = instruction.split(" ")[0]  # get opcode

        if opcode in opcode_frequency_dict.keys():
            opcode_frequency_dict[opcode] += 1
        else :
            opcode_frequency_dict[opcode] = 1

    import operator # to sort dictionary as value
    opcode_frequecy_dict = sorted(opcode_frequency_dict.items(), key=operator.itemgetter(1), reverse=True)

    return opcode_frequecy_dict

def getOpcodeSet(filename, bits='32bit'):

    opcode_set = sorted(list(set(getOpcodeList(filename,bits))))

    return opcode_set

