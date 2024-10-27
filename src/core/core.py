from core import Strings, OpCode, PEHeader, ByteCode, ApiCall
def run(func,dataset,feature_type,out_ext,out_dir):
    content = ""
    if func =="string":
        content = Strings.getStrings(dataset)
    elif func == "opcode":
        content = OpCode.getOpcode(dataset)
    elif func == "api-call":
        content = ApiCall.getApiCall(dataset)
    elif func == "bytecode":
        content = ByteCode.getByteCode(dataset)
    else:
        raise("function should be one of them: string | opcode | api-call | bytecode")
    print(func," ",dataset," ",feature_type," ",out_ext," ",out_dir)

    print(content)