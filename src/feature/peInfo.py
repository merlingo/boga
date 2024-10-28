#!/usr/bin/env python
"""
    Get PE Header information from Portable Executable files.

    It use PeFile project develop  in https://github.com/erocarrera/pefile

#
# Author: Necmettin Çarkacı
#
# E-mail: necmettin [ . ] carkaci [ @ ] gmail [ . ] com
#
# Usage :opcode.py file
#   dataset : file or directory
"""

import array
import math
import pefile


def get_entropy(raw_data):
    """
        Calculate Shannon entropy
        Entropy (x) = -p(x)*log(p(x))

    :param raw_data: Binary digits
    :return: entropy value
    :rtype:float
    """
    if len(raw_data) == 0:
        return 0.0
    occurences = array.array('L', [0] * 256)
    for x in raw_data:
        occurences[x if isinstance(x, int) else ord(x)] += 1

    entropy = 0
    for x in occurences:
        if x:
            p_x = float(x) / len(raw_data)
            entropy -= p_x * math.log(p_x, 2)

    return entropy


def _get_resources(pe):
    """Extract resources :
    [entropy, size]"""
    resources = []
    if hasattr(pe, 'DIRECTORY_ENTRY_RESOURCE'):
        try:
            for resource_type in pe.DIRECTORY_ENTRY_RESOURCE.entries:
                if hasattr(resource_type, 'directory'):
                    for resource_id in resource_type.directory.entries:
                        if hasattr(resource_id, 'directory'):
                            for resource_lang in resource_id.directory.entries:
                                data = pe.get_data(resource_lang.data.struct.OffsetToData, resource_lang.data.struct.Size)
                                size = resource_lang.data.struct.Size
                                entropy = get_entropy(data)

                                resources.append([entropy, size])
        except Exception as e:
            return resources
    return resources


def extractVersionInfo(pe):
    """
        Extract Version Information from PE Header
        :param filename:
        :return: PE Header information map
        :rtype: dict (options, value) -> (strr, float)
    """

    version_info = {}

    for fileinfo in pe.FileInfo:
        if fileinfo.Key == 'StringFileInfo':
            for st in fileinfo.StringTable:
                for entry in st.entries.items():
                    version_info[entry[0]] = entry[1]
        if fileinfo.Key == 'VarFileInfo':
            for var in fileinfo.Var:
                version_info[var.entry.items()[0][0]] = var.entry.items()[0][1]
    if hasattr(pe, 'VS_FIXEDFILEINFO'):
          version_info['flags'] = pe.VS_FIXEDFILEINFO.FileFlags
          version_info['os'] = pe.VS_FIXEDFILEINFO.FileOS
          version_info['type'] = pe.VS_FIXEDFILEINFO.FileType
          version_info['file_version'] = pe.VS_FIXEDFILEINFO.FileVersionLS
          version_info['product_version'] = pe.VS_FIXEDFILEINFO.ProductVersionLS
          version_info['signature'] = pe.VS_FIXEDFILEINFO.Signature
          version_info['struct_version'] = pe.VS_FIXEDFILEINFO.StrucVersion

    return version_info


def extractHeaderInfo(pe):
    """
        Exract information from PE Header

        :param filename:
        :return: PE Header information map
        :rtype: dict (options, value) -> (strr, float)
    """
    header_info = {}

    header_info['Machine'] = pe.FILE_HEADER.Machine
    header_info['SizeOfOptionalHeader'] = pe.FILE_HEADER.SizeOfOptionalHeader
    header_info['Characteristics'] = pe.FILE_HEADER.Characteristics
    header_info['MajorLinkerVersion'] = pe.OPTIONAL_HEADER.MajorLinkerVersion
    header_info['MinorLinkerVersion'] = pe.OPTIONAL_HEADER.MinorLinkerVersion
    header_info['SizeOfCode'] = pe.OPTIONAL_HEADER.SizeOfCode
    header_info['SizeOfInitializedData'] = pe.OPTIONAL_HEADER.SizeOfInitializedData
    header_info['SizeOfUninitializedData'] = pe.OPTIONAL_HEADER.SizeOfUninitializedData
    header_info['AddressOfEntryPoint'] = pe.OPTIONAL_HEADER.AddressOfEntryPoint
    header_info['BaseOfCode'] = pe.OPTIONAL_HEADER.BaseOfCode

    try:
        header_info['BaseOfData'] = pe.OPTIONAL_HEADER.BaseOfData
    except AttributeError:
        header_info['BaseOfData'] = 0

    header_info['ImageBase'] = pe.OPTIONAL_HEADER.ImageBase
    header_info['SectionAlignment'] = pe.OPTIONAL_HEADER.SectionAlignment
    header_info['FileAlignment'] = pe.OPTIONAL_HEADER.FileAlignment
    header_info['MajorOperatingSystemVersion'] = pe.OPTIONAL_HEADER.MajorOperatingSystemVersion
    header_info['MinorOperatingSystemVersion'] = pe.OPTIONAL_HEADER.MinorOperatingSystemVersion
    header_info['MajorImageVersion'] = pe.OPTIONAL_HEADER.MajorImageVersion
    header_info['MinorImageVersion'] = pe.OPTIONAL_HEADER.MinorImageVersion
    header_info['MajorSubsystemVersion'] = pe.OPTIONAL_HEADER.MajorSubsystemVersion
    header_info['MinorSubsystemVersion'] = pe.OPTIONAL_HEADER.MinorSubsystemVersion
    header_info['SizeOfImage'] = pe.OPTIONAL_HEADER.SizeOfImage
    header_info['SizeOfHeaders'] = pe.OPTIONAL_HEADER.SizeOfHeaders
    header_info['CheckSum'] = pe.OPTIONAL_HEADER.CheckSum
    header_info['Subsystem'] = pe.OPTIONAL_HEADER.Subsystem
    header_info['DllCharacteristics'] = pe.OPTIONAL_HEADER.DllCharacteristics
    header_info['SizeOfStackReserve'] = pe.OPTIONAL_HEADER.SizeOfStackReserve
    header_info['SizeOfStackCommit'] = pe.OPTIONAL_HEADER.SizeOfStackCommit
    header_info['SizeOfHeapReserve'] = pe.OPTIONAL_HEADER.SizeOfHeapReserve
    header_info['SizeOfHeapCommit'] = pe.OPTIONAL_HEADER.SizeOfHeapCommit
    header_info['LoaderFlags'] = pe.OPTIONAL_HEADER.LoaderFlags
    header_info['NumberOfRvaAndSizes'] = pe.OPTIONAL_HEADER.NumberOfRvaAndSizes

    return header_info

def exctractSectionInfo(pe):
    """
        Exract section information from PE Header

        :param filename:
        :return: PE Header information map
        :rtype: dict (options, value) -> (strr, float)
    """
    section_info = {}

    # Sections
    section_info['SectionsNb'] = len(pe.sections)
    entropy = list(map(lambda x:x.get_entropy(), pe.sections))
    section_info['SectionsMeanEntropy'] = sum(entropy)/float(len(entropy))
    section_info['SectionsMinEntropy'] = min(entropy)
    section_info['SectionsMaxEntropy'] = max(entropy)
    raw_sizes = list(map(lambda x:x.SizeOfRawData, pe.sections))
    section_info['SectionsMeanRawsize'] = sum(raw_sizes)/float(len(raw_sizes))
    section_info['SectionsMinRawsize'] = min(raw_sizes)
    section_info['SectionsMaxRawsize'] = max(raw_sizes)
    virtual_sizes = list(map(lambda x:x.Misc_VirtualSize, pe.sections))
    section_info['SectionsMeanVirtualsize'] = sum(virtual_sizes)/float(len(virtual_sizes))
    section_info['SectionsMinVirtualsize'] = min(virtual_sizes)
    section_info['SectionMaxVirtualsize'] = max(virtual_sizes)

    return section_info

def exctractImportInfo(pe):
    """
        Exract import information from PE Header

        :param filename:
        :return: PE Header information map
        :rtype: dict (options, value) -> (strr, float)
    """
    import_info = {}

    try:
        import_info['ImportsNbDLL'] = len(pe.DIRECTORY_ENTRY_IMPORT)
        imports = sum([x.imports for x in pe.DIRECTORY_ENTRY_IMPORT], [])
        import_info['ImportsNb'] = len(imports)
        import_info['ImportsNbOrdinal'] = len(list(filter(lambda x:x.name is None, imports)))
    except AttributeError:
        import_info['ImportsNbDLL'] = 0
        import_info['ImportsNb'] = 0
        import_info['ImportsNbOrdinal'] = 0

    return import_info

def exractExportInfo(pe):
    """
        Exract export information from PE Header

        :param filename:
        :return: PE Header information map
        :rtype: dict (options, value) -> (strr, float)
    """
    export_info = {}

    try:
        export_info['ExportNb'] = len(pe.DIRECTORY_ENTRY_EXPORT.symbols)
    except AttributeError:
        # No export
        export_info['ExportNb'] = 0

    #Resources
    resources= _get_resources(pe)
    export_info['ResourcesNb'] = len(resources)
    if len(resources)> 0:
        entropy = list(map(lambda x:x[0], resources))
        export_info['ResourcesMeanEntropy'] = sum(entropy)/float(len(entropy))
        export_info['ResourcesMinEntropy'] = min(entropy)
        export_info['ResourcesMaxEntropy'] = max(entropy)
        sizes = list(map(lambda x:x[1], resources))
        export_info['ResourcesMeanSize'] = sum(sizes)/float(len(sizes))
        export_info['ResourcesMinSize'] = min(sizes)
        export_info['ResourcesMaxSize'] = max(sizes)
    else:
        export_info['ResourcesNb'] = 0
        export_info['ResourcesMeanEntropy'] = 0
        export_info['ResourcesMinEntropy'] = 0
        export_info['ResourcesMaxEntropy'] = 0
        export_info['ResourcesMeanSize'] = 0
        export_info['ResourcesMinSize'] = 0
        export_info['ResourcesMaxSize'] = 0

    return export_info


def excractConfSizeInfo(pe):
    """
        Exract conf size information from PE Header

        :param filename:
        :return: PE Header information map
        :rtype: dict (options, value) -> (strr, float)
    """
    confsize_info = {}


    # Load configuration size
    try:
        confsize_info['LoadConfigurationSize'] = pe.DIRECTORY_ENTRY_LOAD_CONFIG.struct.Size
    except AttributeError:
        confsize_info['LoadConfigurationSize'] = 0


    # Version configuration size
    try:
        version_infos = extractVersionInfo(pe)
        confsize_info['VersionInformationSize'] = len(version_infos.keys())
    except AttributeError:
        confsize_info['VersionInformationSize'] = 0

    return confsize_info



def getInformationFromPEHeader(filename, delimeter=','):
    """
        Exctract information from PE Header

        :param filename:
        :return: PE Header information map
        :rtype: dict (options, value) -> (strr, float)
    """
    information = {}

    try:
        pe = pefile.PE(filename)
    except Exception as e:
        print("PEinfo.getInformationFromPEHeader: header info from pe file can not be extracted - "+ str(e))
        return information #no key attentments which doesnt use pe file here. so if there is not pe file then empty dict is returned
    #pe = pefile.PE(filename)

    information.update(extractHeaderInfo(pe))
    information.update(exctractSectionInfo(pe))
    information.update(exctractImportInfo(pe))
    information.update(exractExportInfo(pe))
    information.update(excractConfSizeInfo(pe))

    return information

def getPEInfoSummary(filename):
    """
        Get PE Header information Summarry
        It use pefile library

        :param filename: Binary filename
        :type filename:str
        :return:
    """
    try:
        pe = pefile.PE(filename)
    except Exception as e:
        print("PEinfo.getPEInfoSummary: header info from pe file can not be extracted - "+str(e))
        return {}  # no key attentments which doesnt use pe file here. so if there is not pe file then empty dict is returned
    return pe.dump_dict()
