#!/usr/bin/env python
"""
#
# Author: Necmettin Çarkacı
#
# E-mail: necmettin [ . ] carkaci [ @ ] gmail [ . ] com
#
# Usage :graph.py file
#   dataset : file or directory
"""

from core import OpCode
import fileutil
import os
def getUndirectedGraph(filename, delimeter=","):

    adjacency_matrix = {}

    opcode_list = OpCode.getOpcodeList(filename)

    for index in range(len(opcode_list) - 1):

        opcode = opcode_list[index]
        suffix_opcode = opcode_list[index + 1]

        cell = opcode+"<-->"+suffix_opcode
        cell_inverse = suffix_opcode + "<-->" + opcode

        if cell in adjacency_matrix.keys():
            adjacency_matrix[cell] += 1

        elif cell_inverse in adjacency_matrix.keys():
            adjacency_matrix[cell_inverse] += 1
        else:
            adjacency_matrix[cell] = 1

    return adjacency_matrix #, opcode_list


def getDirectedGraph(filename, delimeter=","):

    adjacency_matrix = {}

    opcode_list = OpCode.getOpcodeFromFile(filename)
    for index in range(len(opcode_list) - 1):
        opcode = opcode_list[index]
        suffix_opcode = opcode_list[index + 1]

        cell = opcode+"-->"+suffix_opcode

        if cell in adjacency_matrix.keys():
            adjacency_matrix[cell] += 1
        else:
            adjacency_matrix[cell] = 1

    return adjacency_matrix #, opcode_list
def getDirectedGraphMatrix(filename,delimeter=","):
    opcode_list = OpCode.getOpcodeList(filename)
    opcode_set = list(set(opcode_list)).sort()
    len_set = len(opcode_set)
    adjacency_matrix = len_set*[len_set*[0]]
    for index in range(len(opcode_list) - 1):
        opcode = opcode_list[index]
        suffix_opcode = opcode_list[index + 1]
        adjacency_matrix[opcode_set.index(opcode)][opcode_set.index(suffix_opcode)]+=1
    return adjacency_matrix

def getEdgeListGraph(filename,delimeter=" "):
    return toString(EdgeListGraph(filename),delimeter)

def EdgeListGraph(filename):
    base = os.path.splitext(filename)[0]
    dictfile = base +".lnd"
    dict_op = local_enum_dict(filename,dictfile)
    opcode_list = OpCode.getOpcodeList(filename)
    numcode_list = op_to_num(dict_op,opcode_list)
    edge_set = set()
    for index in range(len(numcode_list) - 1):
        num = numcode_list[index]
        suffix_num = numcode_list[index + 1]

        edge_set.add((num,suffix_num))
    edge_list= list(edge_set)
    edge_list.sort(key=lambda tup:tup[0],reverse=False)
    return edge_list

def toString(edge_list,delimeter):
    rstr = ""
    for t in edge_list:
        rstr +=str(t[0])+delimeter+str(t[1])+os.linesep
    return rstr
##### ENUMARATİON SECTİON FOR GRAPH ######
'''
The functions below are used to convert node opcode to integer.
'''

def enum_dict_glob(dirname,dictfile,delimeter):
    #3seçenek: 1eğer dict file varsa, 2eğer yoksa, 3eğer varsa ve fark varsa
    dict_op= dict()
    opcodeset = collect_optonum(dirname)
    dopset = set()#filedaki opcodelar
    if (os.path.isfile(dictfile)):
        dict_op = get_dict(dictfile)
        #eğer fark varsa:
        with open(dictfile, 'r') as df:
            for line in df:
                d = line.split(sep="  ")
                dopset.add(d[1])
            difference = opcodeset.difference(dopset) #eğer toplanan opcodeların dosyada yazanlardan farki var ise guncellenir
        if (difference):
            update_dict(dictfile,difference,d)
    else:
        dict_op = op_num_mapping(opcodeset)
        write_dict(dictfile,dict_op)

    return dict_op

def local_enum_dict(filename,dictfile):
    if (os.path.isfile(dictfile)):
        return get_dict(dictfile)
    else:
        oset = set()
        oset.update(set(OpCode.getOpcodeList(filename)))
        dict_op = op_num_mapping(oset)
        write_dict(dictfile, dict_op)
        return dict_op

def op_num_mapping(opcodeset):
    dict_op= dict()
    i = 1
    for o in opcodeset:
        dict_op[o] = i  # creating dictionary of opcode to num
        i += 1
    return dict_op

def op_to_num(dict,opseq):
    numseq = []
    for o in opseq:
        numseq.append(dict[o])
    return numseq
def num_to_op(dict,numseq):
    opseq = []
    for n in numseq:
        opseq.append(list(dict.keys())[list(dict.values()).index(n)])
    return opseq


def write_dict(filename,data):
    if (os.path.isfile(filename)):
        return
    with open(filename, 'w') as df:
        for i in data.keys():
            s = str(i)+"  "+str(data[i])+"  "
            df.write(s)
            df.write(os.linesep)

def update_dict(filename,difference,d):
    j=1
    with open(filename, 'a') as adf:
        for do in difference:
            s=str(d+j)+"  "+str(do)
            adf.write(s)
            adf.write(os.linesep)

def collect_optonum(dirname):
    files = fileutil.getFilePaths(dirname)
    oset = set()
    for filename in files:
        oset.update(set(OpCode.getOpcodeList(filename)))
    return oset

def get_dict(filename):
    dict_op = dict()
    with open(filename, 'r') as df:
        for line in df:
            d = line.split(sep="  ")
            dict_op[d[0]]=d[1]
    return dict_op

if __name__ == '__main__':
    from lib import output
    filename = "../dataset/putty.exe"
    content = getEdgeListGraph(filename)
    output_ext="edg_lst"
    output.writeIntoFile(filename, output_ext, content)

def getDirectedGraphFromOpcode(opcodefilename, delimeter=","):

    adjacency_matrix = {}
    with open(opcodefilename,'r') as input_file:
        content = input_file.read()
    opcode_list = content.split(delimeter)

    for index in range(len(opcode_list) - 1):
        opcode = opcode_list[index]
        suffix_opcode = opcode_list[index + 1]

        cell = opcode+"-->"+suffix_opcode

        if cell in adjacency_matrix.keys():
            adjacency_matrix[cell] += 1
        else:
            adjacency_matrix[cell] = 1

    return adjacency_matrix #, opcode_list
