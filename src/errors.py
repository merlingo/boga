class UnsupportedFunctionSelectionError(Exception):
    """Exception raised for errors in the case of selecting unsupported function.

    Attributes:
        func -- function selection. 
        message -- explanation of the error
    """

    def __init__(self, func, message="function should be one of them: string | opcode | api-call | bytecode"):
        self.salary = func
        self.message = message
        super().__init__(self.message+": "+func)

class UnsupportedFormatSelectionError(Exception):
    """Exception raised for errors in the case of selecting unsupported format.

    Attributes:
        out_ext -- extension for output file. It also defines the document format
        message -- explanation of the error
    """

    def __init__(self, out_ext, message="Output extension should be one of them: text | seq | vec | dot"):
        self.salary = out_ext
        self.message = message
        super().__init__(self.message+": "+out_ext)

class UnexecutableFormatError(Exception):
    """Exception raised for errors in the case of trying to extract feature in format that cant be executable for the selected function.

    Attributes:
        out_ext -- extension for output file. It also defines the document format
        message -- explanation of the error
    """

    def __init__(self, out_ext, message="Strings can't be extracted in Vector format"):
        self.salary = out_ext
        self.message = message
        super().__init__(self.message+": "+out_ext)

class UnexecutableDisassemblerError(Exception):
    """Exception raised for errors in the case of trying to extract feature in format that cant be executable for the selected function.

    Attributes:
        out_ext -- extension for output file. It also defines the document format
        message -- explanation of the error
    """

    def __init__(self, disassembler, function, message="This disassembler can't execute the function:"):
        self.disassembler = disassembler
        self.function = function
        super().__init__(self.message+": disassembler: "+disassembler + " function:"+ function)