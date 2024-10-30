

import argparse
import os
import core.core
import fileutil
import main
from core import core
from feature import feature


if __name__ == '__main__':
    global_parser = argparse.ArgumentParser(prog="boga")
    global_parser.add_argument("-o","--outfile",help="set filename of output file in csv format. it is for main function",default="output.csv")
    global_parser.add_argument("-d", "--dataset", help="set dataset path. dataset can be directory or file. If dataset not defined, the default dataset dir is [currentdir]/dataset")
    global_parser.add_argument("-a", "--automatic", help="Do analyis job by using .auto file which contains all instructions. If file pat not defined, the default auto file is [currentdir]/main.auto")
    global_parser.add_argument("-i", "--interactive", help="interactive analysis.", action="store_true")
    global_parser.add_argument("-e", "--extension", help="extension list of dataset.", action="append")
   #global_parser.add_argument("-ft", "--feature_type", help="feature type - selection for the feature type included in output file: seq | text | vec | dot")

    subparsers = global_parser.add_subparsers(dest="command",
    title="subcommands", help="static analysis operations"
)

    core_parser = subparsers.add_parser("core", help="core activities - data collection: For each file in dataset, building one out file. Disassemble the file and extract analysis result from it into a file whose name is same but extension is different.Functions: Opcode, string, api-calls, byte code")
    core_parser.add_argument("-f","--func", help="select core function: string | opcode | apicall | bytecode")
    core_parser.add_argument("-ft", "--feature_type", help="feature type - selection for the feature type included in output file: seq | text | vec | dot")
    core_parser.add_argument("-oe", "--output_ext",default="core", help="extension list of output files.")
    core_parser.add_argument("-o", "--out_dir",default="/core", help="directory which is used for output files")


    feature_parser = subparsers.add_parser("feature", help="feature extraction from raw data")
    feature_parser.add_argument("-f","--func", help="select core function: anomalies | exifinfo | graph | header | histogram | import | frequency")
    feature_parser.add_argument("-oe", "--output_ext",default="feature", help="extension list of output files.")
    feature_parser.add_argument("-o", "--out_dir",default="/feature", help="directory which is used for output files")

    signature_parser = subparsers.add_parser("signature", help="building signature by using outputs of raw data or feature")
    signature_parser.add_argument("-f","--func", help="select core function: build | test")
    signature_parser.add_argument("-i", "--input",default="sign", help="extension list of output files.")
    signature_parser.add_argument("-o", "--out_dir",default="/sign", help="directory which is used for output files")

    model_parser = subparsers.add_parser("model", help="building detection or classification models")
    model_parser.add_argument("-f","--func", help="select core function: train | test  | import | export")
    model_parser.add_argument("-i", "--input",default="model", help="extension list of output files.")
    model_parser.add_argument("-o", "--out_dir",default="/model", help="directory which is used for output files")

    args = global_parser.parse_args()
    #print(args.func(*args.operands))

    dataset = args.dataset
    automatic = args.automatic
    extensionList = args.extension
    #feature_type = args.feature_type
    outfile = args.outfile
    cmd = args.command
    print("command:", cmd)

    if(extensionList == None):
        #default extension list
        extensionList= ['.exe', '.dll']
    if(dataset ==None):
        cwd = os.getcwd()
        dataset = cwd+ "/src/dataset"
    #print(dataset)
    #print(extensionList)
    listOfFile = ""
    if os.path.isfile(dataset):
        listOfFile = dataset
    elif os.path.isdir(dataset):
        listOfFile = fileutil.getFilePaths(dataset, extensionList)
    #print(listOfFile)

    if cmd == None:
        main.run(listOfFile,outfile)
    elif(cmd == "core"):
        func = args.func
        feature_type = args.feature_type
        if(feature_type ==None):
            feature_type = "text"
        output_ext = args.output_ext
        out_dir = args.out_dir

        #print(sub_args)
        core.run(func, listOfFile, feature_type, output_ext, out_dir)
    elif(cmd == "feature"):
        func = args.func
        output_ext = args.output_ext
        out_dir = args.out_dir

        #print(sub_args)
        feature.run(func, listOfFile, output_ext, out_dir)
    
    #main.run(listOfFile,outfile)
    #2- core process çalıştırma mekanizması tasarla kodları geçir test et
    #3- feature çalıştırma mekanizması tasarla kodlar geçir test et
    #4- model uygulaması ne yapar tasarla, kodları bul ve uyarla
    #5- signature uygulaması ne yapar tasarla, kodları bul ve uyarla
    #6- interaktive modu kodla
    #7- auto döküman okuyup çalıştırmayı kodla
    #if func == "core":
    #    core.run(listOfFile, feature_type, out_ext="core", out_dir="core_analysis")