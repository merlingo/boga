
import os
import errors
from feature import anomalies, exifInfo, graph, hash, histogramCalculater, peInfo, winApiFrequency, winImportFunctionFrequency
def run(func,dataset,feature_type,out_ext,out_dir):
    content = ""
    for filename in dataset:
        if func =="anomalies":
            anomalies.getAnomalies(filename,out_ext,out_dir)
        elif func == "exifinfo":
            exifInfo.getExifInfo(filename,out_ext,out_dir)
        elif func == "graph":
            graph.getUndirectedGraph(filename,out_ext,out_dir)
        elif func == "header":
            peInfo.getInformationFromPEHeader(filename,out_ext,out_dir)    
        elif func == "histogram":
            histogramCalculater.getHistogram(filename,out_ext,out_dir)    
        elif func == "import":
            winImportFunctionFrequency.getImportTable(filename,out_ext,out_dir)
        elif func == "frequency":
            winApiFrequency.getWinApiListFrequency(filename,out_ext,out_dir)
        else:
            raise errors.UnsupportedFunctionSelectionError(func)
    print(func," ",dataset," ",feature_type," ",out_ext," ",out_dir)

