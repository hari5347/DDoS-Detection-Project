## DDoS detection from network traffic

Step 1 : Obtain network traffic datasets for training the models.

https://kb.mazebolt.com/knowledgebase/slowloris-attack/
https://kb.mazebolt.com/knowledgebase/http-flood/
https://www.pcapanalysis.com/pcap-downloads/denial-of-service-dos/denial-of-service-attack-traffic-sample-pcap-file-download/

pcap2csv.py can be used for extracting features out of the pcap files in csv format.

python3 pcap2csv.py

Converted datasets are provided in Data/.

Step 2 : Train different models.

SVM and Decision Tree were used here.

Step 3 : Set up three Virtual Machines and configure the network, install apache2 server in one of the VMs.

Step 4 : Deploy a sample website in the server.

Step 5 : Install Slowloris in one other VM.

https://github.com/gkbrk/slowloris

Used to simulate DDoS traffic.

Step 6 : Capture network traffic from the Host machine using tshark.

Step 7 : Convert the pcap files to csv and use the pre-trained models to perform classification.

python3 Modelling.py 


