

import argparse
import os
import fileutil
import main
if __name__ == '__main__':
    global_parser = argparse.ArgumentParser(prog="boga")
    global_parser.add_argument("outfile",default="output.csv")
    global_parser.add_argument("-d", "--dataset", help="set dataset path. dataset can be directory or file. If dataset not defined, the default dataset dir is [currentdir]/dataset")
    global_parser.add_argument("-a", "--automatic", help="Do analyis job by using .auto file which contains all instructions. If file pat not defined, the default auto file is [currentdir]/main.auto")
    global_parser.add_argument("-i", "--interactive", help="interactive analysis.", action="store_true")
    global_parser.add_argument("-e", "--extension", help="extension list of dataset.", action="append")
    global_parser.add_argument("-ft", "--feature_type", help="feature type - selection for the feature type included in output file: seq | text | vec | dot")

    subparsers = global_parser.add_subparsers(
    title="subcommands", help="static analysis operations"
)
    arg_template = {
    "dest": "operands",
    "type": float,
    "nargs": 2,
    "metavar": "OPERAND",
    "help": "a numeric value",
}
    core_parser = subparsers.add_parser("core", help="core activities - data collection")
    core_parser.add_argument(**arg_template)
    core_parser.set_defaults(func="core")

    feature_parser = subparsers.add_parser("feature", help="feature extraction from raw data")
    feature_parser.add_argument(**arg_template)
    feature_parser.set_defaults(func="feature")

    signature_parser = subparsers.add_parser("signature", help="building signature by using outputs of raw data or feature")
    signature_parser.add_argument(**arg_template)
    signature_parser.set_defaults(func="signature")

    model_parser = subparsers.add_parser("model", help="building detection or classification models")
    model_parser.add_argument(**arg_template)
    model_parser.set_defaults(func="model")
    args = global_parser.parse_args()
    #print(args.func(*args.operands))

    dataset = args.dataset
    automatic = args.automatic
    extensionList = args.extension
    feature_type = args.feature_type
    outfile = args.outfile
    if(extensionList == None):
        #default extension list
        extensionList= ['.exe', '.dll']
    if(dataset ==None):
        cwd = os.getcwd()
        dataset = cwd+ "/src/dataset"
    if(feature_type ==None):
        feature_type = "text"
    print(dataset)
    print(extensionList)
    listOfFile = ""
    if os.path.isfile(dataset):
        listOfFile = dataset
    elif os.path.isdir(dataset):
        listOfFile = fileutil.getFilePaths(dataset, extensionList)
    print(listOfFile)
    main.run(listOfFile,outfile)
    #1- ana uygulama ne yapar; karar ver tasarla ve kodla 
    #2- core process çalıştırma mekanizması tasarla kodları geçir test et
    #3- feature çalıştırma mekanizması tasarla kodlar geçir test et
    #4- model uygulaması ne yapar tasarla, kodları bul ve uyarla
    #5- signature uygulaması ne yapar tasarla, kodları bul ve uyarla
    #6- interaktive modu kodla
    #7- auto döküman okuyup çalıştırmayı kodla
    