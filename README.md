![Analytic Bull agains malware](profile.png)

# BOGA - STATIC ANALYSIS OF PE FILES
## Purpose
Boga is a tool to analyze windows' applications to extract some information. The general use of the boga would be on the dataset which includes many pe files. Also, it produces a csv document which includes many features extracted from the dataset. By that way, malware detection model can be created. This tool has been used for the study of metamorphic/polymorphic malware detection and classification researches.

## How to install
You can install on both linux machine or docker. 
### Docker Installation
docker run -it $(docker build -q .)

### Linux Installation
Need to install python:
- sudo apt-get install python3

Then install required packages by using requirements.txt
- pip install -r requirements.txt

## How to Use
You can use the app in 3 ways: in interactive mode, by cli, in automation mode.

