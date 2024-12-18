#!/usr/bin/env python
#
# File uitility library. The library has useful functions on running file system.
# Each function has different aim.
#
# Author: Necmettin Çarkacı
# E-mail: necmettin [ . ] carkaci [ @ ] gmail [ . ] com
#
# Usage :


import os, sys, time, random
import hashlib, csv


def getFilePaths(directory, extensionList=[], reverse=False):
    """
        Collect all files from given directory and return their paths list

        :param directory :directory name
        :type directory :str
        :param extensionList: file extension, using for file type filter.
        :type extensionList: str (Default value is [])
        :param reverse :
        :type reverse: bool( Default value is False)
        :return list of paths of files
        :rtype:list
	"""

    file_paths = []

    for root, directories, files in os.walk(directory):
        for filename in files:
            if (len(extensionList) > 0):  # get speified extension files
                extension = os.path.splitext(filename)[1]

                if ((extension.lower() in extensionList) or (extension.upper() in extensionList)):
                    if (not reverse):
                        filepath = os.path.join(root, filename)
                        file_paths.append(filepath)
                        # print (filepath)
                elif (reverse):
                    filepath = os.path.join(root, filename)
                    file_paths.append(filepath)

            else:  # get all files
                filepath = os.path.join(root, filename)
                file_paths.append(filepath)
                # print (filepath)

    print("Number of file found : " + str(len(file_paths)))
    return file_paths


def groupFilesAsSize(listOfFile):
    """
        Get list of files and return a dictionary group as file size.

        :param listOfFile :list of file path
        :type listOfFile : list
        :return : file names grouped as size
        :rtype:<dict> (<key><value>) : key : size, value : filename
	"""

    fileGroupDict = {}  # <key><value> --> <size> [list of file names]

    for filename in listOfFile:
        size = os.path.getsize(filename)

        if size in fileGroupDict.keys():  # or if fileGroupDict.get(size, []):
            fileGroupDict[size].append(filename)
        else:
            fileGroupDict[size] = []  # create list for value of key
            fileGroupDict[size].append(filename)

    # print (fileGroupDict)
    print("Number of group : " + str(len(fileGroupDict)))
    return fileGroupDict


def groupFilesAsExtension(listOfFile):
    """
        Get list of files and return a dictionary group as file type.
        It check file type as extension

        :param listOfFile : list of file path
        :type listOfFile :list
        :return
        :rtype:<dict> (<key><value>) : key : type, value : filename

        # TODO : make file type cheking as file header information
	"""
    fileGroupDict = {}  # <key><value> --> <size> [list of file names]

    for filename in listOfFile:
        extension = os.path.splitext(filename)[1]

        if extension in fileGroupDict.keys():  # or if fileGroupDict.get(size, []):
            fileGroupDict[extension].append(filename)
        else:
            fileGroupDict[extension] = []  # create list for value of key
            fileGroupDict[extension].append(filename)

    # print (fileGroupDict)
    print("Number of group : " + str(len(fileGroupDict)))
    return fileGroupDict


def filterUniqueGroupFromDict(fileGroupDict):
    """
        Get file group dictionary return non-unique groups in dictionary
        Non-unique group in dictionary means it key has multiple value

        :param fileGroupDict : file group
        :type fileGroupDict :dict
        :return : non-unique groups in dictionary
        :rtype:dict
	"""
    uniqueFileSizeDict = {}

    for size in fileGroupDict:
        listOfFile = fileGroupDict[size]
        if (len(listOfFile) > 1):
            uniqueFileSizeDict[size] = listOfFile

    # print (uniqueFileSizeDict)
    print("Number of group after filtering : " + str(len(uniqueFileSizeDict)))
    return uniqueFileSizeDict


def getFileHash(filename, fastHash=False, buf=(1024 * 1024)):
    """
        Calculate md5 hash value for given file and return the value
        if fast hash enabled, it calculate fast hashing.
        Fast hashing meaning it get specific part of the file header and calculate hash for this part.
        Fast hashing part size can give as parameter

        :param filename :file path
        :type filename :str
        :param fastHash :  Specific part of the file header hashing. This enabled for big file hashing process. Default value is False
        :type fastHash :bool
        :param buf :Fast hashing size. Default value is 1024*1024 = 1 megabyte
        :type buf :int
        :return: hash value of file
        :rtype:str
    """

    hasher = hashlib.md5()
    with open(filename, 'rb') as file:

        if (fastHash):
            chunk = file.read(buf)
            while len(chunk) > 0:
                hasher.update(chunk)
                chunk = file.read(buf)
        else:
            content = file.read()
            hasher.update(content)

    # print(hasher.hexdigest())

    return hasher.hexdigest()

def moveFiles(listOfFile, destinationDir):
    """
        Move list of the files into different directory
        If the same name file exists, it add random prefix into filename

        :param listOfFile : <string list> list of file path
        :type listOfFile:str
        :param destinationDir :Destination directory name
        :type destinationDir:str
        :return void
    """

    for filename in listOfFile:
        path, name = os.path.split(filename)
        prefix_num = random.randrange(1, 99999999)

        if not os.path.exists(destinationDir):
            os.makdirs(destinationDir)

        destinationFilename = os.getcwd() + os.sep + destinationDir + os.sep + str(prefix_num) + "_"
        os.rename(filename, destinationFilename + name)



def renameFileWithHashValue(directory):
    """
        Collect deeply all files from directory and calculate md5 hash values of the files,
        And rename the files with their hash values

        :param directory: directory name
        :type directory:str
        :return: void
    """

    listOfFiles = getFilePaths(directory)

    for sourceFilename in listOfFiles:
        hashValue = getFileHash(sourceFilename)
        path, name = os.path.split(sourceFilename)
        ext = name.split('.')[-1]
        destinationFilename = path + os.sep + hashValue + '.' + ext
        os.rename(sourceFilename, destinationFilename)

def changeFileExtension(directory, newExt, oldExt='.*'):
    """
    Collect deeply all files from directory and change their extensions

    :param directory :directory name
    :type directory:str
    :param oldExt :old file extension type
    :type oldExt:str
    :param newExt :new file extension type
    :type newExt:str
    :return void

    """
    listOfFiles = getFilePaths(directory)

    for sourceFilename in listOfFiles:
        # print (sourceFilename)
        basefilename = os.path.splitext(sourceFilename)[0]
        extension = os.path.splitext(sourceFilename)[1]

        if oldExt != '.*':
            if sourceFilename.endswith(oldExt):
                destinationFilename = basefilename + newExt
                os.rename(sourceFilename, destinationFilename)
        else:
            destinationFilename = basefilename + newExt
            os.rename(sourceFilename, destinationFilename)



def writeIntoFile(filename, out_dir, extension, content, sep=','):

    # start function variables
    dirname         = os.path.dirname(filename)


    filename        = os.path.basename(filename)
    (filename, ext) = os.path.splitext(filename)
    output_filename = dirname+os.sep+out_dir+os.sep+filename+'.'+extension

    os.makedirs(os.path.dirname(output_filename), exist_ok=True)
    with open(output_filename, 'w') as output_file:
        output_file.write(content)

def getAttrList(dictlist):
    # dictlist den fieldnameleri topla (ilk deger hash)
    fset = set()
    fs_hash = set()

    for dictionary in dictlist:
        
        dk = list(dictionary.keys())
        if dk.__contains__("hash"):
            dk.remove("hash")
        fset.update(dk)
        #fs_hash.add(dictionary["hash"])  # hashleri topla

    fs_hash.update()
    return fset,fs_hash
def writeSingleIntoCSVFile(filename,dictlist, delimeter=','):
    print("features are collecting")
    fset, fs_hash = getAttrList(dictlist) #fset is all fields in dictionary

    #fset.add("hash")
    #print("done: "+str(len(fset)))
    csv_filename = filename + '.csv'
    directory = os.path.dirname(csv_filename)
    print(csv_filename)
    if not os.path.exists(directory):
        os.makedirs(directory)
    with open(csv_filename, 'w') as output_file:

        writer = csv.DictWriter(output_file,delimiter=delimeter,fieldnames=list(fset))
        writer.writeheader()
        t = len(dictlist)
        i=1
        for d in dictlist:#adding fields which is not in d but in other, to d
            len_d = len(fset.difference(set(d.keys())))
            if(len_d >=0 ):
                print("length of difference: "+str(len_d))
                #for k  in fset.difference(set(d.keys())):
                #   d[k]=0
            print(str(i)+" - "+str(t))
            i+=1
            writer.writerow(d)
        print("csv has just been written")