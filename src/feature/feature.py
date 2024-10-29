
import os
import errors
import fileutil
from feature import anomalies, exifInfo, graph, hash, histogramCalculater, peInfo, winApiFrequency, winImportFunctionFrequency
def run(func,dataset,feature_type,out_ext,out_dir):
    content = []
    for index, filename in enumerate(dataset):

        if func =="anomalies":
            content.append(anomalies.getAnomalies(filename))
        elif func == "exifinfo":
            content.append(exifInfo.getExifInfo(filename))
        elif func == "graph":
            content.append(graph.getUndirectedGraph(filename))
        elif func == "header":
            content.append(peInfo.getInformationFromPEHeader(filename)   ) 
        elif func == "histogram":
            content.append( histogramCalculater.getHistogram(filename)   ) 
        elif func == "import":
            content.append( winImportFunctionFrequency.getImportTable(filename))
        elif func == "frequency":
            content.append( winApiFrequency.getWinApiListFrequency(filename))
        else:
            raise errors.UnsupportedFunctionSelectionError(func)
            
        if content is not None:
            
            # Write informations into csv file
            outfile = os.path.dirname(filename)+os.sep+out_dir+os.sep+os.path.basename(filename)+"."+out_ext
            try:
                fileutil.writeSingleIntoCSVFile(outfile, content)
            except IOError as ioe:
                print(str(ioe))
   
