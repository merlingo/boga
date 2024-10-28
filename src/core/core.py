from core import Strings, OpCode, PEHeader, ApiCall
import os

from . import errors
def run(func,dataset,feature_type,out_ext,out_dir):
    content = ""
    for filename in dataset:
        if func =="string":
            Strings.getStrings(filename,out_ext,out_dir)
        elif func == "opcode":
            OpCode.getOpcode(filename,out_ext,out_dir)
        elif func == "api-call":
            ApiCall.getApiCall(filename,out_ext,out_dir)
        elif func == "header":
            PEHeader.getPeHeaderInformation(filename,out_ext,out_dir)    
        else:
            raise errors.UnsupportedFunctionSelectionError(func)
    print(func," ",dataset," ",feature_type," ",out_ext," ",out_dir)

