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
import errors
import fileutil
def extractAsText(iterable):
    content = ""
    for (offset, size, instruction, hexdump) in iterable:
        # To avoid TypeError: a bytes-like object is required, not 'str'
        print(instruction)
        #instruction = instruction.decode()

        opcode = instruction.split(" ")[0]  # get opcode
        content += opcode+"\n"
    return content

def extractAsSeq(iterable):
    content = ""
    for (offset, size, instruction, hexdump) in iterable:
        # To avoid TypeError: a bytes-like object is required, not 'str'
        #instruction = instruction.decode()

        opcode = instruction.split(" ")[0]  # get opcode
        content += opcode+","
    return content
    
def extractAsVec(iterable):
    content = ""
    for (offset, size, instruction, hexdump) in iterable:
        # To avoid TypeError: a bytes-like object is required, not 'str'
        #print(instruction)
        #instruction = instruction.decode()
        delimeter = ","
        opcode = delimeter.join(instruction.split(" "))  # get opcode
        content += str(offset)+","+ str(size)+"," + str(hexdump)+","+opcode+"\n"
    return content



def getOpcode(filename, out_ext, out_dir, bits='32bit'):

    iterable = Disassembler.diassemble(filename,bits)
    content = ""
    if out_ext == "text":
        content = extractAsText(iterable)
    elif out_ext == "seq":
        content= extractAsSeq(iterable)
    elif out_ext == "vec":
        content = extractAsVec(iterable=iterable)
    elif out_ext == "dot":
        raise errors.UnexecutableFormatError(out_ext)
    else:
        raise errors.UnsupportedFormatSelectionError(out_ext)    
    fileutil.writeIntoFile(filename,out_dir,out_ext,content)
    return content

def getOpcodeList(filename, bits='32bit'):

    iterable = Disassembler.diassemble(filename,bits)

    opcode_code_list = []
    for (offset, size, instruction, hexdump) in iterable:

        # To avoid TypeError: a bytes-like object is required, not 'str'
        #instruction = instruction.decode()

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

