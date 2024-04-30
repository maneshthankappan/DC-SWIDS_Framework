# DC-SWIDS_Framework
This repository is a part of our research work entitled  
  <p align="center"> <img src="https://github.com/maneshthankappan/DC-SWIDS_Framework/blob/main/title.png"></p>
and describes how to detect MC-MitM attacks using their signatures in a protected Wi-Fi network. This project provides how an ADS node (Raspberri Pi) of our DC-SWIDS framework works. 

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

### Our primary considerations in Wi-Fi adapter selection were twofold

* Cost-Effectiveness and Commercial Availability: We aimed to choose Wi-Fi adapters that are affordable and readily accessible in the market.
* Support for Monitor Mode in Linux Distributions: We required adapters that could reliably operate in monitor mode across various Linux distributions.
  
For monitoring the 2.4 GHz band, our experiments primarily involved the High Gain TP-Link TL-WN722N V3 and the ALFA AWUS036NHA adapters. We observed similar detection performance with both options but ultimately opted for the TL-WN722N V3 due to its commercial availability and cost-effectiveness, typically priced between $10 and $15.
In the case of monitoring the 5 GHz band, our main contenders were the High Gain Wi-Fi Nation and the Netis WF2180 adapters. We noted approximately 20% higher detection performance with the High Gain Wi-Fi Nation adapter compared to the Netis option. Consequently, we selected the High Gain Wi-Fi Nation adapter for 5 GHz band monitoring. These adapters are commercially available within the price range of $25 to $30.
We believe that these choices strike a balance between cost-effectiveness and performance, allowing us to effectively monitor both the 2.4 GHz and 5 GHz bands in our experiments. 
Attach any two commercially available Wi-Fi adapters. One is used to monitor taget AP's channel and other is used to observe retransmission of frames (as part of MC-MitM) in any other channels other than AP's channel. We use TP-Link WN722N v3 (High Gain) Wi-Fi adapters for 2.4 Ghz and Wi-Fi Nation for 5GHz channels. Please note that only one frequency can be monitored at a time. Ensure that both Wi-Fi adapters are physically connected to your system before proceeding.

## Quick Start

From this repository, download all the 3 files (DC-SWIDS_script.py and macaddresses.json) and keep all of them in a same folder. 
### Description of Python Scripts
* ##### DC-SWIDS_script.py: 
The following script prompts the user to  the SSID of the target access point (AP) in the Wi-Fi network. It then automatically identifies all clients connected to the AP and forwards their MAC addresses for monitoring module. Its main purpose is to identify the presence of MC-MitM attacks by verifying the status of stage 1 and stage 2 attacks based on attack signatures. Various MC-MitM attack signatures created are avialable in [MC-MitM-Attack-Dataset](https://github.com/maneshthankappan/MC-MitM-Attack-Dataset) "DC-SWIDS_script.py" implements the detection logic described in section 5 of our previous paper titled [A Signature-Based Wireless Intrusion Detection System Framework for Multi-Channel Man-in-the-Middle Attacks Against Protected Wi-Fi Networks](https://ieeexplore.ieee.org/abstract/document/10423016)  As such, this script is designed to be executed with a probe interval of 60 seconds. After the first probe interval, the same script will be executed in another thread with a delay of 10 seconds. This approach ensures continuous monitoring, allowing the an ADS node of DC-SWIDS framework to make attack decisions every 10 seconds after the initial probe interval. 
Furthermore, this script automatically select Wi-Fi cards and put them in monitor mode for passively monitoring the operating channel and if any oher unauthorized or rogue channels found. 
### Important Functions/varialbles and Libraries used
* **Library Imports**:Libraries for GUI creation (PyQt5), thread handling (QThread, pyqtSignal, QObject), datetime operations, network packet handling (scapy), MQTT communication, and system operations are imported.
* **Initialization of Global Variables**:Various global variables like interfaces (iface1, iface2), network identifiers (bssid, essid, channel), timing settings (probe_interval, launch_interval), and lists (mac_list) are initialized.
* **MQTT Setup**:An MQTT client is configured to connect to a broker and subscribe to topics related to different types of network attacks.
File Handling:An output file is opened to log results from the detection processes.
* **Classes for Network Monitoring**:BssidChannelHopper and EssidChannelHopper: These classes extend QThread and are used to change the channel on the network interface to hop through different frequencies either based on BSSID or ESSID.
ClientScanner: A class to scan for clients on the network by sniffing packets and identifying unique MAC addresses.
* **IdsThread**: Extends QThread and QObject to handle different types of sniffing for malicious activities, and communicating findings via MQTT.
GUI Class (Window):Defines the main window for the application using PyQt5. It includes functionality to start network scanning, switch between different GUI screens, and display network clients and logs.
* **Execution and Event Handling**:Functions to search for clients by modifying the network interface to monitor mode, handle application closing, and retrieve vendor information based on MAC addresses are defined.At the end of the script, the GUI application is initialized and executed, which sets up the main window and enters the application event loop.
* **Detection Threads**:These threads monitor for specific types of network traffic and analyze it for potential malicious activities, such as jamming attacks and rogue access points, by sniffing and analyzing packets.

* ##### macaddresses.json:    
This file is utilized by the "DC-SWIDS_script.py" to retrieve the vendor details of connected clients by using their MAC addresses

## How to run the SWIDS

In the terminal, write  
```bash
sudo python3 DC-SWIDS_script.py
```
After executing this DC-SWIDS_script.py, we launch various MC-MitM attack variants. 
* [Click here how to launch MC-MitM base variant](https://github.com/maneshthankappan/Multi-Channel-Man-in-the-Middle-Attacks-Against-Protected-Wi-Fi-Networks-By-Base-Variant-) 
* [Click here how to launch MC-MitM improved variant](https://github.com/maneshthankappan/Multi-Channel-Man-in-the-Middle-Attacks-Against-Protected-Wi-Fi-Networks-By-Improved-Variant)


## Sample GUIs-Proof of concept
### Front panel of an ADS node
<p align="center"> <img src="https://github.com/maneshthankappan/DC-SWIDS_Framework/blob/main/GUI1-new-updated.png"></p>

### Log file view of an ADS node
<p align="center"> <img src="https://github.com/maneshthankappan/DC-SWIDS_Framework/blob/main/GUI2-new-updated.png"></p>

## References
  * https://github.com/vanhoefm/mc-mitm
  * https://github.com/vanhoefm/modwifi
  * https://github.com/lucascouto/mitm-channel-based-package
  * https://www.krackattacks.com/
  * https://www.fragattacks.com/#tools
  * https://papers.mathyvanhoef.com/acsac2014.pdf
  * https://papers.mathyvanhoef.com/ccs2018.pdf


