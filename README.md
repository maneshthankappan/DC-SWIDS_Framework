# DC-SWIDS_Framework
This repository is a part of our research work entitled 
  <p align="center"> <img src="[https://github.com/maneshthankappan/MC-MitM-Attack-Dataset/blob/main/Labels/title.png](https://github.com/maneshthankappan/DC-SWIDS_Framework/blob/main/title.png)"></p>
and describes how to detect MC-MitM attack signatures. This code provides how an ADS node (Raspberri Pi) of our DC-SWIDS framework works  Kindly refer to our above research paper for more details of MC-MitM attacks and their variants.

## Prerequisite-Install Scapy
To install Scapy on Raspberry Pi , you can follow these steps:

Open a terminal in Raspberry Pi . 

Update the package lists by running the following command:
```
sudo apt update
```
Once the package lists are updated, you can install Scapy by running the following command:
```
sudo apt install python3-scapy
```
During the installation, you may be prompted to confirm the installation by typing 'Y' and pressing Enter.
After the installation is complete, you should have Scapy installed on your Raspberri Pi
You can verify the installation by running the following command:

```
scapy
```
This should start the Scapy interactive shell if the installation was successful.

## Prerequisite-Attach Wi-Fi adapters

###Our primary considerations in Wi-Fi adapter selection were twofold

* Cost-Effectiveness and Commercial Availability: We aimed to choose Wi-Fi adapters that are affordable and readily accessible in the market.
* Support for Monitor Mode in Linux Distributions: We required adapters that could reliably operate in monitor mode across various Linux distributions.
  
For monitoring the 2.4 GHz band, our experiments primarily involved the High Gain TP-Link TL-WN722N V3 and the ALFA AWUS036NHA adapters. We observed similar detection performance with both options but ultimately opted for the TL-WN722N V3 due to its commercial availability and cost-effectiveness, typically priced between $10 and $15.
In the case of monitoring the 5 GHz band, our main contenders were the High Gain Wi-Fi Nation and the Netis WF2180 adapters. We noted approximately 20% higher detection performance with the High Gain Wi-Fi Nation adapter compared to the Netis option. Consequently, we selected the High Gain Wi-Fi Nation adapter for 5 GHz band monitoring. These adapters are commercially available within the price range of $25 to $30.
We believe that these choices strike a balance between cost-effectiveness and performance, allowing us to effectively monitor both the 2.4 GHz and 5 GHz bands in our experiments. 
Attach any two commercially available Wi-Fi adapters. One is used to monitor taget AP's channel and other is used to observe retransmission of frames (as part of MC-MitM) in any other channels other than AP's channel. We use TP-Link WN722N v3 (High Gain) Wi-Fi adapters for 2.4 Ghz and Wi-Fi Nation for 5GHz channels. Please note that only one frequency can be monitored at a time. Ensure that both Wi-Fi adapters are physically connected to your system before proceeding.

## Quick Start

From this repository, download all the 3 files (SWIDS.py,mc-mitm-detection-asyncsniffer_centralized.py, and macaddresses.json) and keep all of them in a same folder. Alternatively you can download SWIDS.tar.gz. 
### Description of Python Scripts
* ##### DC-SWIDS_Framework.py: 
The following script prompts the user to  the SSID of the target access point (AP) in the Wi-Fi network. It then automatically identifies all clients connected to the AP and forwards their MAC addresses. 

Make sure you have the "mc-mitm-detection-asyncsniffer_centralized.py" script in the same directory, or provide the full path to the script if it's located elsewhere. This script will pass the selected Wi-Fi card, Wi-Fi frequency, and SSID as command-line arguments to the "mc-mitm-detection-asyncsniffer_centralized.py" script, which will handle the further processing.
* ##### macaddresses.json:
This file is utilized by the "SWIDS.py" script to retrieve the vendor details of connected clients by using their MAC addresses.
* ##### mc-mitm-detection-asyncsniffer_centralized.py: 
This script combines various detection logic discussed in Section 5 of our paper with the algorithms presented in Appendix 1. Its main purpose is to identify the presence of MC-MitM attacks by verifying the status of stage 1 and stage 2 attacks based on attack signatures. For more detailed information, please refer to Section 3 of our paper.

The script is designed to be executed with a probe interval of 60 seconds. After the first probe interval, the same script will be executed in another thread with a delay of 10 seconds. This approach ensures continuous monitoring, allowing the SWIDS to make attack decisions every 10 seconds after the initial probe interval.

## How to run the SWIDS

In the terminal, write  
```bash
sudo python3 SWIDS.py
```
After executing this SWIDS.py, we launch various MC-MitM attack variants. 
* [Click here how to launch MC-MitM base variant](https://github.com/maneshthankappan/Multi-Channel-Man-in-the-Middle-Attacks-Against-Protected-Wi-Fi-Networks-By-Base-Variant-) 
* [Click here how to launch MC-MitM improved variant](https://github.com/maneshthankappan/Multi-Channel-Man-in-the-Middle-Attacks-Against-Protected-Wi-Fi-Networks-By-Improved-Variant)


### Sample output snippet
We provide a sample output snippet from the logfile of our SWIDS

