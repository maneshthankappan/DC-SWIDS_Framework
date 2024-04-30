# Import necessary modules for the application including networking, system operations, GUI elements, and MQTT communication.
from PyQt5 import QtCore, QtGui, QtWidgets
from PyQt5.QtCore import QThread, pyqtSignal, QObject
from datetime import datetime, timedelta, date

from impacket.dot11 import Dot11, RadioTap
from impacket.eap import EAPOL
from scapy.all import *
import subprocess
import statistics
import json
import sys
import os
import re
import time
from time import time, sleep
from scapy.layers.eap import EAPOL
from scapy.sendrecv import AsyncSniffer, sniff
import datetime
import statistics
import sys
import paho.mqtt.client as mqtt
import paho.mqtt.publish as publish
from scapy.layers.dot11 import Dot11Beacon, Dot11ProbeResp, Dot11Elt
# Declare global variables for network interfaces, timing, and MQTT client setup.
iface1 = "wlan1"
iface2 = "wlan2"
bssid = ""
essid = ""
freq = ""
channel = ""
broad_mac = "ff:ff:ff:ff:ff:ff"   # Broadcast MAC address for wide network capture
probe_interval = 60  # Interval for scanning
launch_interval = 10 # Interval between launching new threads
packet_num = 1000 # Number of packets to capture in sniffing
mac_list = [] # List to store detected MAC addresses
r_flag = True   # Running flag to control thread execution
start = time()
start_datetime = datetime.datetime.now()
duration = 120
max_time = 60  # 60 secs   for managing co-operative module through MQTT
start_time = time()  # remember when we started
mac_json = "macaddresses.json"
output_file = open("logfile.txt", "a")  # Open a log file for appending data
mqttBroker = "broker.emqx.io"
client = mqtt.Client("ADS Node")  # Initialize MQTT client
client.connect(mqttBroker) # Connect to the MQTT broker

# Subscribe to various MQTT topics for different types of network attacks.
client.subscribe("const_jam_attack_mqtt")
client.subscribe("react_jam_attack_mqtt")
client.subscribe("csa_attack_mqtt")
client.subscribe("con_beacon_probe_mqtt")
client.subscribe("con_connection_est_mqtt")
client.subscribe("con_data_mqtt")

file_obj = open(output_file, "a+") # Open or create another log file


# Class to handle channel hopping on the BSSID level for both 2.4 GHz and 5 GHz frequencies.
class BssidChannelHopper(QThread):
    def __init__(self):
        QThread.__init__(self)

    def run(self):
        global freq, channel, bssid
        if freq == "2,4 Ghz":
            print("channel hopper bssid 2.4 running")
            for i in range(15)[1::]:
                subprocess.run(["iw", iface1, "set", "channel", str(i)])
                sleep(0.35)
                if bssid != "":
                    break
        elif freq == "5 Ghz":
            for i in ["36", "40", "44", "48", "52", "56", "60", "64", "68", "72", "76", "80", "84", "88", "92",
                      "96", "100", "104", "108", "112", "116", "120", "124", "128", "132", "136", "140", "144", "149",
                      "153",
                      "157", "161", "165", "169", "173", "177", "181"]:
                subprocess.run(["iw", iface1, "set", "channel", i])
                sleep(0.35)
                if bssid != "":
                    break

# Class for hopping channels based on ESSID. Similar to BSSID hopping but uses a different utility and checks for ESSID changes.
class EssidChannelHopper(QThread):
    def __init__(self):
        QThread.__init__(self)

    def run(self):
        global freq, channel, essid
        if freq == "2,4 Ghz":
            for i in range(15)[1::]:
                subprocess.run(["iwconfig", iface1, "channel", str(i)])
                sleep(0.35)
                if essid != "":  # if essid is different from the initial value and changed by the get_essid() function the for loop brakes and the channel hopper stops
                    break
        elif freq == "5 Ghz":
            for i in ["36", "40", "44", "48", "52", "56", "60", "64", "68", "72", "76", "80", "84", "88", "92",
                      "96", "100", "104", "108", "112", "116", "120", "124", "128", "132", "136", "140", "144", "149",
                      "153",
                      "157", "161", "165", "169", "173", "177", "181"]:
                subprocess.run(["iwconfig", iface1, "channel", i])
                sleep(0.35)
                if essid != "":  # if essid is different from the initial value and changed by the get_essid() function the for loop brakes and the channel hopper stops
                    break


class ClientScanner(QThread):
    def __init__(self, object):
        QThread.__init__(self)
        self.object = object

    def run(self):
        global client_sniffer, bssid, mac_list

        def callbackfunc(frame):
            if frame.haslayer(Dot11) and frame[Dot11].type == 2 and frame[Dot11].addr1 == bssid:
                if "33:33" not in frame[Dot11].addr2 and "01:00:5e" not in frame[Dot11].addr2 and frame[
                    Dot11].addr2 not in mac_list:
                    self.object.clients_list.addItem(
                        f"{frame[Dot11].addr2.upper()} - {get_vendor(frame[Dot11].addr2.upper())}")
                    mac_list.append(frame[Dot11].addr2)
                    self.object.start_button.setEnabled(True)
            elif frame.haslayer(Dot11) and "33:33" not in frame[Dot11].addr1 and "01:00:5e" not in frame[
                Dot11].addr1 and frame[Dot11].type == 2 and frame[Dot11].addr2 == bssid:
                if frame[Dot11].addr1 != "ff:ff:ff:ff:ff:ff" and frame[Dot11].addr1 not in mac_list:
                    self.object.clients_list.addItem(
                        f"{frame[Dot11].addr1.upper()} - {get_vendor(frame[Dot11].addr1.upper())}")
                    mac_list.append(frame[Dot11].addr1)
                    self.object.start_button.setEnabled(True)
            sleep(0.3)

        print("scanner running")
        client_sniffer = AsyncSniffer(iface=iface1, prn=callbackfunc)
        client_sniffer.start()


class IdsThread(QThread, QObject):
    def __init__(self, client_mac, instance_num):
        QObject.__init__(self)
        QThread.__init__(self)
        self.client_mac = client_mac
        self.instance_num = instance_num

    to_launcher_signal = pyqtSignal(str)

    def run(self):
        global output_file
        self.cnt0: int = 0
        self.cnt1: int = 0
        self.cnt2: int = 0
        self.cnt3: int = 0
        self.cnt4_deauth: int = 0
        self.cnt4_disass: int = 0
        self.cnt5_auth_seq_real: int = 0
        self.cnt6_assoc_resp_real: int = 0
        self.cnt7_eapol_real: int = 0
        self.cnt5_auth_seq_rogue: int = 0
        self.cnt6_assoc_resp_rogue: int = 0
        self.cnt7_eapol_rogue: int = 0
        self.cnt8_data_real: int = 0
        self.cnt8_data_rogue: int = 0
        self.bccc: int = 0
        self.bcfc: int = 0
        self.pccc: int = 0
        self.pcfc: int = 0
        self.pccc: int = 0
        self.pcfc: int = 0

        self.r_flag = True
        self.starttime = time()
        self.endtime = time() + probe_interval
        self.start_datetime = datetime.now()
        self.duration = 120

        self.const_jam_attack = 0
        self.react_jam_attack = 0
        self.csa_attack = 0

        self.con_beacon_probe = 0
        self.con_connection_est = 0
        self.con_data = 0
        self.stage_1_attack_traffic = 0
        self.stage_2_attack_traffic = 0
        self.today = datetime.now()
        self.t = []  # List for managing FIAT
        self.temp = 0
        self.beacon = 0  # beacon counter for couting beacons during constant jamming attack

        self.constant_jamming_sniffer = AsyncSniffer(iface=iface1, count=packet_num, prn=self.constant_jamming_callback,
                                                     store=0, monitor=True)
        self.reactive_jamming_sniffer = AsyncSniffer(iface=iface1, count=packet_num, prn=self.reactive_jamming_callback,
                                                     store=0, monitor=True)
        self.channel_switch_sniffer = AsyncSniffer(iface=iface1, count=packet_num, prn=self.channel_switch_callback,
                                                   store=0, monitor=True)
        self.concurrent_beacon_sniffer_real = AsyncSniffer(iface=iface1, count=packet_num,
                                                           prn=self.concurrent_beacon_real_callback, store=0,
                                                           monitor=True)
        self.concurrent_beacon_sniffer_rogue = AsyncSniffer(iface=iface2, count=packet_num,
                                                            prn=self.concurrent_beacon_rogue_callback, store=0,
                                                            monitor=True)
        self.concurrent_probe_resp_sniffer_real = AsyncSniffer(iface=iface1, count=packet_num,
                                                               prn=self.concurrent_probe_resp_real_callback, store=0,
                                                               monitor=True)
        self.concurrent_probe_resp_sniffer_rogue = AsyncSniffer(iface=iface2, count=packet_num,
                                                                prn=self.concurrent_probe_resp_rogue_callback, store=0,
                                                                monitor=True)
        self.concurrent_auth_sniffer_real = AsyncSniffer(iface=iface1, count=packet_num,
                                                         prn=self.concurrent_auth_real_callback, store=0, monitor=True)
        self.concurrent_auth_sniffer_rogue = AsyncSniffer(iface=iface2, count=packet_num,
                                                          prn=self.concurrent_auth_rogue_callback, store=0,
                                                          monitor=True)
        self.concurrent_association_sniffer_real = AsyncSniffer(iface=iface1, count=packet_num,
                                                                prn=self.concurrent_association_real_callback, store=0,
                                                                monitor=True)
        self.concurrent_association_sniffer_rogue = AsyncSniffer(iface=iface2, count=packet_num,
                                                                 prn=self.concurrent_association_rogue_callback,
                                                                 store=0, monitor=True)
        self.concurrent_eapol_sniffer_real = AsyncSniffer(iface=iface1, count=packet_num,
                                                          prn=self.concurrent_eapol_real_callback, store=0,
                                                          monitor=True)
        self.concurrent_eapol_sniffer_rogue = AsyncSniffer(iface=iface2, count=packet_num,
                                                           prn=self.concurrent_eapol_rogue_callback, store=0,
                                                           monitor=True)
        self.concurrent_data_sniffer_real = AsyncSniffer(iface=iface1, count=packet_num,
                                                         prn=self.concurrent_data_real_callback, store=0, monitor=True)
        self.concurrent_data_sniffer_rogue = AsyncSniffer(iface=iface2, count=packet_num,
                                                          prn=self.concurrent_data_rogue_callback, store=0,
                                                          monitor=True)

        self.constant_jamming_sniffer.start()
        self.reactive_jamming_sniffer.start()
        self.channel_switch_sniffer.start()
        self.concurrent_beacon_sniffer_real.start()
        self.concurrent_beacon_sniffer_rogue.start()
        self.concurrent_probe_resp_sniffer_real.start()
        self.concurrent_probe_resp_sniffer_rogue.start()
        self.concurrent_auth_sniffer_real.start()
        self.concurrent_auth_sniffer_rogue.start()
        self.concurrent_association_sniffer_real.start()
        self.concurrent_association_sniffer_rogue.start()
        self.concurrent_eapol_sniffer_real.start()
        self.concurrent_eapol_sniffer_rogue.start()
        self.concurrent_data_sniffer_real.start()
        self.concurrent_data_sniffer_rogue.start()

        while self.endtime > time():
            sleep(3)

        self.constant_jamming_sniffer.stop()
        self.reactive_jamming_sniffer.stop()
        self.channel_switch_sniffer.stop()
        self.concurrent_beacon_sniffer_real.stop()
        self.concurrent_beacon_sniffer_rogue.stop()
        self.concurrent_probe_resp_sniffer_real.stop()
        self.concurrent_probe_resp_sniffer_rogue.stop()
        self.concurrent_auth_sniffer_real.stop()
        self.concurrent_auth_sniffer_rogue.stop()
        self.concurrent_association_sniffer_real.stop()
        self.concurrent_association_sniffer_rogue.stop()
        self.concurrent_eapol_sniffer_real.stop()
        self.concurrent_eapol_sniffer_rogue.stop()
        self.concurrent_data_sniffer_real.stop()
        self.concurrent_data_sniffer_rogue.stop()

        def on_message(client, userdata, message):
            global const_jam_attack_mqtt, react_jam_attack_mqtt, csa_attack_mqtt, con_beacon_probe_mqtt, con_connection_est_mqtt, con_data_mqtt
            # print("Topic: ", str(message.topic), " Received message: ", str(message.payload.decode("utf-8")))
            # print("hai")
            if str(message.topic) == "const_jam_attack_mqtt":
                const_jam_attack_mqtt = int(str(message.payload.decode("utf-8")))
                # print("const_jam_attack from mqtt: ", const_jam_attack_mqtt)
            if str(message.topic) == "react_jam_attack_mqtt":
                react_jam_attack_mqtt = int(str(message.payload.decode("utf-8")))
                # print("react_jam_attack from mqtt: ", react_jam_attack_mqtt)
            if str(message.topic) == "csa_attack_mqtt":
                csa_attack_mqtt = int(str(message.payload.decode("utf-8")))
                # print("csa_attack from mqtt: ", csa_attack_mqtt)
            if str(message.topic) == "con_beacon_probe_mqtt":
                con_beacon_probe_mqtt = int(str(message.payload.decode("utf-8")))
                # print("con_beacon_probe from mqtt: ", con_beacon_probe_mqtt)
            if str(message.topic) == "con_connection_est_mqtt":
                con_connection_est_mqtt = int(str(message.payload.decode("utf-8")))
                # print("con_connection_est from mqtt: ", con_connection_est_mqtt)
            if str(message.topic) == "con_data_mqtt":
                con_data_mqtt = int(str(message.payload.decode("utf-8")))
                # print("con_data from mqtt: ", con_data_mqtt)

        def mqtt_timeout():
            run = True
            print(Fore.GREEN + "Co-operative unit is observing........")
            while run:
                if (time() - start_time) > max_time:
                    client.loop_stop()
                    client.disconnect()
                    # print("Script Ended: Ran For " + str(time() - start_time) + " seconds, limit was " + str(max_time))
                    run = False
            return

        client.on_message = on_message
        client.loop_start()

        thread = Thread(target=mqtt_timeout)
        thread.start()




        self.t.append(0.02)
        self.t.append(0.01)
        self.t.append(0.011)
        self.t.pop(0)
        self.var = statistics.pvariance(self.t)
        self.fiat_std = statistics.pstdev(self.t)
        self.fdr = (self.beacon / 200) * 100

        if self.fiat_std > 2 and self.fdr > 0.3:
            self.const_jam_attack = 1
            self.stage_1_attack_traffic = 1
        if self.cnt2 > 10:
            self.react_jam_attack = 1
            self.stage_1_attack_traffic = 1
        if self.cnt0 > 1:
            self.csa_attack = 1
            self.stage_1_attack_traffic = 1

        if self.bccc > 0 and self.bcfc > 0 and self.pccc > 0 and self.pcfc > 0:
            self.con_beacon_probe = 1

        if (self.cnt5_auth_seq_real > 0 or self.cnt6_assoc_resp_real > 0 or self.cnt7_eapol_real > 0) and (
                self.cnt5_auth_seq_rogue > 0 or self.cnt6_assoc_resp_rogue > 0 or self.cnt7_eapol_rogue > 0):
            self.con_connection_est = 1

        if self.cnt8_data_real > 0 and self.cnt8_data_rogue > 0:
            self.con_data = 1

        if self.con_beacon_probe == 1 and (self.con_connection_est == 1 or self.con_data == 1):
            self.stage_2_attack_traffic = 1

        self.to_launcher_signal.emit(
            f"-------Results from probe interval number {self.instance_num} for client {self.client_mac} started at {self.start_datetime}----------------\n")
        file_obj.write(
            f"-------Results from probe interval number {self.instance_num} for client {self.client_mac} started at {self.start_datetime}----------------\n")
        self.to_launcher_signal.emit("Const Jamming -FIAT =")
        file_obj.write("Const Jamming -FIAT =")
        self.to_launcher_signal.emit(str(self.fiat_std) + '\n')
        file_obj.write(str(self.fiat_std) + '\n')
        self.to_launcher_signal.emit("Const Jamming -FDR =")
        file_obj.write("Const Jamming -FDR =")
        self.to_launcher_signal.emit(str(self.fdr) + '\n')
        file_obj.write(str(self.fdr) + '\n')
        self.to_launcher_signal.emit("Malformed_Beacon_Count =")
        file_obj.write("Malformed_Beacon_Count =")
        self.to_launcher_signal.emit(str(self.cnt2) + '\n')
        file_obj.write(str(self.cnt2) + '\n')
        self.to_launcher_signal.emit("CSA_Count =")
        file_obj.write("CSA_Count =")
        self.to_launcher_signal.emit(str(self.cnt0) + '\n')
        file_obj.write(str(self.cnt0) + '\n')
        self.to_launcher_signal.emit("--------PREDICTED COUNTS OF STAGE 2 ATTACK TRAFFIC----------------\n")
        file_obj.write("--------PREDICTED COUNTS OF STAGE 2 ATTACK TRAFFIC----------------\n")
        self.to_launcher_signal.emit(
            "Beacons on real channel : {0} \nBeacons on rogue channel : {1}".format(self.bccc, self.bcfc))
        file_obj.write("Beacons on real channel : {0} \nBeacons on rogue channel : {1}".format(self.bccc, self.bcfc))
        self.to_launcher_signal.emit(
            "Probe Response on real channel : {0} \nProbe Response on rogue channel : {1}".format(self.pccc, self.pcfc))
        file_obj.write(
            "Probe Response on real channel : {0} \nProbe Response on rogue channel : {1}".format(self.pccc, self.pcfc))
        self.to_launcher_signal.emit("Auth on real channel_Count =")
        file_obj.write("Auth on real channel_Count =")
        self.to_launcher_signal.emit(str(self.cnt5_auth_seq_real) + '\n')
        file_obj.write(str(self.cnt5_auth_seq_real) + '\n')
        self.to_launcher_signal.emit("Auth on rogue channel_Count =")
        file_obj.write("Auth on rogue channel_Count =")
        self.to_launcher_signal.emit(str(self.cnt5_auth_seq_rogue) + '\n')
        file_obj.write(str(self.cnt5_auth_seq_rogue) + '\n')
        self.to_launcher_signal.emit("Association  on real channel_Count =")
        file_obj.write("Association  on real channel_Count =")
        self.to_launcher_signal.emit(str(self.cnt6_assoc_resp_real) + '\n')
        file_obj.write(str(self.cnt6_assoc_resp_real) + '\n')
        self.to_launcher_signal.emit("Association  on rogue channel_Count =")
        file_obj.write("Association  on rogue channel_Count =")
        self.to_launcher_signal.emit(str(self.cnt6_assoc_resp_rogue) + '\n')
        file_obj.write(str(self.cnt6_assoc_resp_rogue) + '\n')
        self.to_launcher_signal.emit("EAPOL  on real channel_Count =")
        file_obj.write("EAPOL  on real channel_Count =")
        self.to_launcher_signal.emit(str(self.cnt7_eapol_real) + '\n')
        file_obj.write(str(self.cnt7_eapol_real) + '\n')
        self.to_launcher_signal.emit("EAPOL  on rogue channel_Count =")
        file_obj.write("EAPOL  on rogue channel_Count =")
        self.to_launcher_signal.emit(str(self.cnt7_eapol_rogue) + '\n')
        file_obj.write(str(self.cnt7_eapol_rogue) + '\n')
        self.to_launcher_signal.emit("Data  on real channel_Count =")
        file_obj.write("Data  on real channel_Count =")
        self.to_launcher_signal.emit(str(self.cnt8_data_real) + '\n')
        file_obj.write(str(self.cnt8_data_real) + '\n')
        self.to_launcher_signal.emit("Data  on rogue channel_Count =")
        file_obj.write("Data  on rogue channel_Count =")
        self.to_launcher_signal.emit(str(self.cnt8_data_rogue) + '\n')
        file_obj.write(str(self.cnt8_data_rogue) + '\n')
        self.to_launcher_signal.emit("-------------PREDICTED STATUS OF ATTACK TRAFFIC-------------\n")
        file_obj.write("-------------PREDICTED STATUS OF ATTACK TRAFFIC-------------\n")
        self.to_launcher_signal.emit("Stage 1 attack traffic =")
        file_obj.write("Stage 1 attack traffic =")
        self.to_launcher_signal.emit(str(self.stage_1_attack_traffic) + '\n')
        file_obj.write(str(self.stage_1_attack_traffic) + '\n')
        self.to_launcher_signal.emit("Stage 2 attack traffic =")
        file_obj.write("Stage 2 attack traffic =")
        self.to_launcher_signal.emit(str(self.stage_2_attack_traffic) + '\n')
        file_obj.write(str(self.stage_2_attack_traffic) + '\n')
        self.to_launcher_signal.emit("-----------------------------END------------------------\n")
        file_obj.write("-----------------------------END------------------------\n")

        self.to_launcher_signal.emit("-Final Decision-\n")
        file_obj.write("-Final Decision-\n")
        self.to_launcher_signal.emit("---------------------------------------------------------\n")
        file_obj.write("---------------------------------------------------------\n")
        if self.const_jam_attack == 1 and self.stage_2_attack_traffic == 1:
            self.to_launcher_signal.emit("Constant Jamming Attack Found\n")
            file_obj.write("Constant Jamming Attack Found\n")
            self.to_launcher_signal.emit("MC-MitM Base Variant Attack\n")
            file_obj.write("MC-MitM Base Variant Attack\n")
        if self.react_jam_attack == 1 and self.stage_2_attack_traffic == 1:
            self.to_launcher_signal.emit("Reactive Jamming Attack Found\n")
            file_obj.write("Reactive Jamming Attack Found\n")
            self.to_launcher_signal.emit("MC-MitM Base Variant Attack\n")
            file_obj.write("MC-MitM Base Variant Attack\n")
        if self.csa_attack == 1 and self.stage_2_attack_traffic == 1:
            self.to_launcher_signal.emit("\nFake CSA attack Found\n")
            file_obj.write("\nFake CSA attack Found\n")
            self.to_launcher_signal.emit("MC-MitM Improved Variant Attack\n")
            file_obj.write("MC-MitM Improved Variant Attack\n")
        if self.stage_1_attack_traffic == 0 and self.stage_2_attack_traffic == 1:
            self.to_launcher_signal.emit("MC-MitM Attack Found\n")
            file_obj.write("MC-MitM Attack Found\n")
            self.to_launcher_signal.emit("Attack Variant Unidentified\n")
            file_obj.write("Attack Variant Unidentified\n")
        if self.stage_1_attack_traffic == 0 and self.stage_2_attack_traffic == 1:
            self.to_launcher_signal.emit("Intentional Jamming Attack Found\n")
            file_obj.write("Intentional Jamming Attack Found\n")
        if self.stage_1_attack_traffic == 0 and self.stage_2_attack_traffic == 0:
            self.to_launcher_signal.emit("No MC-MitM Attack\n")
            file_obj.write("No MC-MitM Attack\n")
        self.to_launcher_signal.emit("---------------------------------------------------------\n")
        file_obj.write("---------------------------------------------------------\n")
        self.end = time()
        self.to_launcher_signal.emit(f"Elapsed time is: ")
        file_obj.write(f"Elapsed time is: ")
        self.to_launcher_signal.emit(str(round((self.end - self.starttime) / 60, 2)))
        file_obj.write(str(round((self.end - self.starttime) / 60, 2)))
        self.to_launcher_signal.emit(" Minutes\n")
        file_obj.write(" Minutes\n")

    # callbacks
    def constant_jamming_callback(self, frame):
        if frame.haslayer(Dot11Beacon):
            bssid_addr = frame[Dot11].addr3
            if bssid_addr == bssid:
                iat = frame.time - self.temp
                self.t.append(iat)
                self.temp = frame.time
                self.beacon += 1

    def reactive_jamming_callback(self, frame):
        if frame.haslayer(Dot11):
            b_addr = frame[Dot11].addr3
            if b_addr == bssid and (frame.haslayer(Dot11Beacon) or frame.haslayer(Dot11ProbeResp)):
                rl = frame.getlayer(RadioTap)
                if rl.Flags == "FCS+badFCS":
                    self.cnt2 += 1

    def channel_switch_callback(self, frame):
        if frame.haslayer(Dot11):
            b_addr = frame[Dot11].addr3
            if b_addr == bssid and (frame.haslayer(Dot11Beacon) or frame.haslayer(Dot11ProbeResp)):
                frame_elt = frame[Dot11Elt]
                while frame_elt:
                    if frame_elt.ID == 37:
                        self.cnt0 += 1
                    frame_elt = frame_elt.payload

    def concurrent_beacon_real_callback(self, frame):
        if frame.haslayer(Dot11Beacon):
            getssid = str(frame.info)
            ap_ssid = getssid[2:len(getssid) - 1]
            local_bssid = frame[Dot11].addr3
            frequency = frame[RadioTap].Channel
            current_channel = (frequency - 2407) // 5
            # Extract Channel
            if (local_bssid == bssid or essid == getssid) and current_channel == 1:
                self.bccc += 1

    def concurrent_beacon_rogue_callback(self, frame):
        if frame.haslayer(Dot11Beacon):
            getssid = str(frame.info)
            ap_ssid = getssid[2:len(getssid) - 1]
            local_bssid = frame[Dot11].addr3
            frequency = frame[RadioTap].Channel
            current_channel = (frequency - 2407) // 5
            # Extract Channel
            if (local_bssid == bssid or essid == getssid) and current_channel != 1:
                self.bcfc += 1

    def concurrent_probe_resp_real_callback(self, frame):
        if frame.haslayer(Dot11ProbeResp):
            getssid = str(frame.info)
            ap_ssid = getssid[2:len(getssid) - 1]
            local_bssid = frame[Dot11].addr3
            frequency = frame[RadioTap].Channel
            current_channel = (frequency - 2407) // 5
            # Extract Channel
            if (local_bssid == bssid or essid == getssid) and current_channel == 1:
                self.pccc += 1

    def concurrent_probe_resp_rogue_callback(self, frame):
        if frame.haslayer(Dot11ProbeResp):
            getssid = str(frame.info)
            ap_ssid = getssid[2:len(getssid) - 1]
            local_bssid = frame[Dot11].addr3
            frequency = frame[RadioTap].Channel
            current_channel = (frequency - 2407) // 5
            # Extract Channel
            if (local_bssid == bssid or essid == getssid) and current_channel != 1:
                self.pcfc += 1

    def concurrent_auth_real_callback(self, frame):
        if frame.haslayer(Dot11) and frame[Dot11].type == 0 and frame[Dot11].subtype == 11:
            local_bssid = frame[Dot11].addr3
            s_mac = frame[Dot11].addr2
            d_mac = frame[Dot11].addr1
            frequency = frame[RadioTap].Channel  # Extract Channel
            current_channel = (frequency - 2407) // 5
            if local_bssid == bssid and (
                    (s_mac == self.client_mac) or (d_mac == self.client_mac)) and current_channel == 1:
                self.cnt5_auth_seq_real += 1

    def concurrent_auth_rogue_callback(self, frame):
        if frame.haslayer(Dot11) and frame[Dot11].type == 0 and frame[Dot11].subtype == 11:
            local_bssid = frame[Dot11].addr3
            s_mac = frame[Dot11].addr2
            d_mac = frame[Dot11].addr1
            frequency = frame[RadioTap].Channel  # Extract Channel
            current_channel = (frequency - 2407) // 5
            if local_bssid == bssid and (
                    (s_mac == self.client_mac) or (d_mac == self.client_mac)) and current_channel != 1:
                self.cnt5_auth_seq_rogue += 1

    def concurrent_association_real_callback(self, frame):
        if frame.haslayer(Dot11) and frame[Dot11].type == 0 and frame[Dot11].subtype == 1:
            local_bssid = frame[Dot11].addr3
            s_mac = frame[Dot11].addr2
            d_mac = frame[Dot11].addr1
            frequency = frame[RadioTap].Channel  # Extract Channel
            current_channel = (frequency - 2407) // 5
            if local_bssid == bssid and (
                    (s_mac == self.client_mac) or (d_mac == self.client_mac)) and current_channel == 1:
                self.cnt6_assoc_resp_real += 1

    def concurrent_association_rogue_callback(self, frame):
        if frame.haslayer(Dot11) and frame[Dot11].type == 0 and frame[Dot11].subtype == 1:
            local_bssid = frame[Dot11].addr3
            s_mac = frame[Dot11].addr2
            d_mac = frame[Dot11].addr1
            frequency = frame[RadioTap].Channel  # Extract Channel
            current_channel = (frequency - 2407) // 5
            if local_bssid == bssid and (
                    (s_mac == self.client_mac) or (d_mac == self.client_mac)) and current_channel != 1:
                self.cnt6_assoc_resp_rogue += 1

    def concurrent_eapol_real_callback(self, frame):
        if frame.haslayer(EAPOL) and (frame[Dot11].type != 1):
            local_bssid = frame[Dot11].addr3
            s_mac = frame[Dot11].addr2
            d_mac = frame[Dot11].addr1
            frequency = frame[RadioTap].Channel  # Extract Channel
            current_channel = (frequency - 2407) // 5
            if bssid == local_bssid and (
                    (s_mac == self.client_mac) or (d_mac == self.client_mac)) and current_channel == 1:
                self.cnt7_eapol_real += 1

    def concurrent_eapol_rogue_callback(self, frame):
        if frame.haslayer(EAPOL) and (frame[Dot11].type != 1):
            local_bssid = frame[Dot11].addr3
            s_mac = frame[Dot11].addr2
            d_mac = frame[Dot11].addr1
            frequency = frame[RadioTap].Channel  # Extract Channel
            current_channel = (frequency - 2407) // 5
            if local_bssid == bssid and (
                    (s_mac == self.client_mac) or (d_mac == self.client_mac)) and current_channel != 1:
                self.cnt7_eapol_rogue += 1

    def concurrent_data_real_callback(self, frame):
        if frame.haslayer(Dot11) and frame[Dot11].subtype == 40:
            local_bssid = frame[Dot11].addr3
            s_mac = frame[Dot11].addr2
            d_mac = frame[Dot11].addr1
            frequency = frame[RadioTap].Channel  # Extract Channel
            current_channel = (frequency - 2407) // 5
            if bssid == local_bssid and (
                    (s_mac == self.client_mac) or (d_mac == self.client_mac)) and current_channel == 1:
                self.cnt8_data_real += 1

    def concurrent_data_rogue_callback(self, frame):
        if frame.haslayer(Dot11) and frame[Dot11].subtype == 40:
            local_bssid = frame[Dot11].addr3
            s_mac = frame[Dot11].addr2
            d_mac = frame[Dot11].addr1
            frequency = frame[RadioTap].Channel  # Extract Channel
            current_channel = (frequency - 2407) // 5
            if local_bssid == bssid and ((s_mac == self.client_mac) or (
                    d_mac == self.client_mac)) and current_channel != 1:
                self.cnt8_data_rogue += 1


class LauncherThread(QThread, QObject):
    def __init__(self, client_mac):
        QThread.__init__(self)
        QObject.__init__(self)
        self.client_mac = client_mac

    to_main_signal = pyqtSignal(str)

    def run(self):
        self.instance_threadlist = []
        instance_num = 1
        while True:
            self.start_new_thread = time() + launch_interval
            self.instance_threadlist.append(IdsThread(self.client_mac, instance_num))
            self.instance_threadlist[len(self.instance_threadlist) - 1].start()
            print(f"Instance num {instance_num} started for client mac address: {self.client_mac}")
            self.to_main_signal.emit(f"Instance num {instance_num} started for client mac address: {self.client_mac}\n")
            file_obj.write(f"Instance num {instance_num} started for client mac address: {self.client_mac}\n")
            self.instance_threadlist[len(self.instance_threadlist) - 1].to_launcher_signal.connect(self.to_main)
            instance_num += 1
            while self.start_new_thread > time():
                sleep(5)

    def to_main(self, text):
        self.to_main_signal.emit(text)


class Window(QObject):
    def __init__(self, mainwindow):
        QObject.__init__(self)
        # clients screen
        self.window = mainwindow
        self.window.setFixedWidth(700)
        self.window.setFixedHeight(420)
        self.centralwidget = QtWidgets.QWidget(self.window)
        self.centralwidget.setEnabled(True)
        self.window.setCentralWidget(self.centralwidget)

        self.stackedwidget = QtWidgets.QStackedWidget(self.centralwidget)
        self.stackedwidget.setGeometry(0, 0, 700, 420)
        self.stackedwidget.setEnabled(True)
        self.clients_screen = QtWidgets.QWidget()
        self.stackedwidget.addWidget(self.clients_screen)
        self.log_screen = QtWidgets.QWidget()
        self.stackedwidget.addWidget(self.log_screen)

        self.ids_label = QtWidgets.QLabel(self.clients_screen)
        self.ids_label.setText(
            "<html><span style='color: black; font-size: 16px'>Autonomous Detection System</span></html>")
        self.ids_label.setGeometry(245, -30, 210, 100)

        self.control_panel_label = QtWidgets.QLabel(self.clients_screen)
        self.control_panel_label.setText(
            "<html><span style='color: black; font-size: 16px'>Control Panel</span></html>")
        self.control_panel_label.setGeometry(35, 0, 105, 100)

        self.ssid_label = QtWidgets.QLabel(self.clients_screen)
        self.ssid_label.setText("<html><span style='color: black;'>Enter SSID: </span></html>")
        self.ssid_label.setGeometry(35, 110, 140, 100)
        self.ssid_lineedit = QtWidgets.QLineEdit(self.clients_screen)
        self.ssid_lineedit.setGeometry(155, 150, 140, 20)

        self.search_button = QtWidgets.QPushButton(self.clients_screen)
        self.search_button.setText("Search clients")
        self.search_button.setGeometry(185, 190, 110, 20)

        self.clients_list_label = QtWidgets.QLabel(self.clients_screen)
        self.clients_list_label.setText(
            "<html><span style='color: black; font-size: 16px'>Connected Wi-Fi Clients</span></html>")
        self.clients_list_label.setGeometry(325, 0, 300, 100)

        self.clients_list = QtWidgets.QListWidget(self.clients_screen)
        self.clients_list.setGeometry(325, 70, 340, 290)

        self.start_button = QtWidgets.QPushButton(self.clients_screen)
        self.start_button.setText("Start ADS")
        self.start_button.setGeometry(555, 380, 110, 20)
        self.start_button.setEnabled(False)

        # log screen
        self.bssid_label = QtWidgets.QLabel(self.log_screen)
        self.bssid_label.setGeometry(20, 10, 320, 40)
        self.bssid_label.setText(
            "<html><head/><body><p><span style=\" font-size:14pt;\">BSSID: CB:86:73:65:8C:D5</span></p></body></html>")

        self.essid_label = QtWidgets.QLabel(self.log_screen)
        self.essid_label.setGeometry(20, 40, 320, 40)
        self.essid_label.setText(
            "<html><head/><body><p><span style=\" font-size:14pt;\">ESSID: Smart-Home-AP2 </span></p></body></html>")

        self.date_label = QtWidgets.QLabel(self.log_screen)
        self.date_label.setGeometry(500, 10, 320, 40)
        self.date_label.setText(
            f"<html><head/><body><p><span style=\" font-size:14pt;\">Date: {str(date.today())}</span></p></body></html>")

        self.time_label = QtWidgets.QLabel(self.log_screen)
        self.time_label.setGeometry(500, 40, 320, 40)
        self.time_label.setText(
            f"<html><head/><body><p><span style=\" font-size:14pt;\">Time: {str(datetime.now().strftime('%H:%M'))}</span></p></body></html>")

        self.textbox = QtWidgets.QTextEdit(self.log_screen,
                                           lineWrapMode=QtWidgets.QTextEdit.FixedColumnWidth,
                                           lineWrapColumnOrWidth=140,
                                           readOnly=True
                                           )
        self.textbox_font = QtGui.QFont()
        self.textbox_font.setFamily("Calibri")
        self.textbox_font.setPixelSize(12)
        self.textbox.setFont(self.textbox_font)
        self.textbox.setGeometry(20, 100, 660, 280)

        self.stop_button = QtWidgets.QPushButton(self.log_screen)
        self.stop_button.setText("Stop ADS")
        self.stop_button.setGeometry(620, 390, 60, 20)

        self.search_button.clicked.connect(lambda: search_clients())
        self.start_button.clicked.connect(lambda: self.start_ids())
        self.stop_button.clicked.connect(lambda: stop_app())

        self.window.closeEvent = stop_app

    def search_clients(self):
        global freq, bssid, essid
        self.bssid_channel_hopper = BssidChannelHopper()
        self.essid_channel_hopper = EssidChannelHopper()
        self.clients_scanner = ClientScanner(self)
        inp = self.ssid_lineedit.text()
        freq = self.freq_combobox.currentText()

        if re.search(r"([0-9A-Fa-f]{2}[:-]){5}([0-9A-Fa-f]{2})|([0-9a-fA-F]{4}\\.[0-9a-fA-F]{4}\\.[0-9a-fA-F]{4})$",
                     inp.strip()):
            bssid = inp.replace("-", ":").lower()
            self.essid_channel_hopper.start()

            def callback(frame):
                global essid, channel
                if frame.haslayer(Dot11Beacon) and frame[Dot11].addr2 == bssid:
                    essid = frame[Dot11Elt].info.decode()
                    channel = frame[Dot11].channel

            while essid == "":
                sniff(iface=iface1, count=5, prn=callback)

        else:
            essid = inp
            self.bssid_channel_hopper.start()

            def callback(frame):
                global bssid, channel
                if frame.haslayer(Dot11Beacon) and frame[Dot11Elt].info.decode() == essid:
                    bssid = frame[Dot11].addr2
                    channel = frame[Dot11].channel

            while bssid == "":
                sniff(iface=iface1, count=5, prn=callback)

        self.clients_scanner.start()

    def start_ids(self):
        self.stackedwidget.setCurrentIndex(1)

        client_sniffer.stop()
        self.launcher_threadlist = []
        for client in mac_list:
            self.launcher_threadlist.append(LauncherThread(client))
            self.launcher_threadlist[len(self.launcher_threadlist) - 1].start()
            self.launcher_threadlist[len(self.launcher_threadlist) - 1].to_main_signal.connect(self.add_to_textbox)
            self.add_to_textbox(f"IDS thread started for client mac address: {client}\n")
            print(f"IDS thread started for client mac address: {client}")
            file_obj.write(f"IDS thread started for client mac address: {client}\n")

    def add_to_textbox(self, text):
        f"<html><head/><body><p><span style=\" font-size:14pt;\">MAC ID         Device Name</span></p></body></html>")
        self.textbox.setPlainText(self.textbox.toPlainText() + text)


def search_clients():
    global iface1
    iface1 = ui.iface_combobox.currentText()
    subprocess.run(["ifconfig", iface1, "down"])
    subprocess.run(["iwconfig", iface1, "mode", "monitor"])
    subprocess.run(["ifconfig", iface1, "up"])
    ui.search_clients()


def stop_app():
    file_obj.close()
    exit()


def get_vendor(mac_address):
    file = open(mac_json, "r")
    dict = json.load(file)
    file.close()
    for i in dict:
        macprefix_len = len(i["macPrefix"])
        if i["macPrefix"] in mac_address[:macprefix_len]:
            return i["vendorName"]
    return "Unknown vendor"


app = QtWidgets.QApplication(sys.argv)
MainWindow = QtWidgets.QMainWindow()
MainWindow.setWindowTitle("DC-SWIDS")
ui = Window(MainWindow)
MainWindow.show()
sys.exit(app.exec_())
