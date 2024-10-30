
import pefile
import fileutil
import errors
def getPeHeaderInformation(filename,out_ext,out_dir, delimeter=','):
    
    """
    Return PE Header information of the file
    :param filename: PE filename
    :type filename:str
    :param delimeter:
    :return:PE Header informations
    :rtype:dict
    """
    peHeader_info = {}
    if out_ext != "text":
        raise errors.UnexecutableFormatError(out_ext)
    try:
        pe              = pefile.PE(filename)
        peHeader_info   = pe.dump_dict()
        fileutil.writeIntoFile(filename,out_dir,out_ext,str(peHeader_info))
        return str(peHeader_info)

    except:

        return None