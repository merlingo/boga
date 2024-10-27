
import pefile

def getPeHeaderInformation(filename, delimeter=','):
    """
    Return PE Header information of the file
    :param filename: PE filename
    :type filename:str
    :param delimeter:
    :return:PE Header informations
    :rtype:dict
    """
    peHeader_info = {}

    try:
        pe              = pefile.PE(filename)
        peHeader_info   = pe.dump_dict()

        return str(peHeader_info)

    except:

        return None