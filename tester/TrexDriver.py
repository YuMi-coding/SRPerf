#!/usr/bin/env python3

import sys
import dpkt
import traceback
from time import sleep

# get TRex APIs.
# sys.path.insert(0, "/opt/trex-core-2.41/scripts/automation/trex_control_plane/stl/")
sys.path.insert(0, "/opt/trex-core-2.95/scripts/automation/trex_control_plane/interactive/")


from trex_stl_lib.api import *

class TrexOutput():

    def __init__(self):
        # We use a dictionary to represent (internally) the TrexOutput 'class'. 
        self.output = {}

        # We create and return a dictionary used to store results of the run.
        # The dictionary is composed by:
        # 
        # dictionary 
        #     |
        #     +--tx
        #     |   +--port
        #     |   +--total_packets
        #     |
        #     +--rx
        #     |   +--port
        #     |   +--total_packets
        #     |
        #     +--warnings

        self.output['tx'] = {}
        self.output['rx'] = {}
        self.output['tx']['port'] = -1
        self.output['tx']['total_packets'] = -1
        self.output['tx']['duration'] = -1
        self.output['tx']['requested_tx_rate'] = -1

        self.output['rx']['port'] = -1
        self.output['rx']['total_packets'] = -1
        self.output['warnings'] = None

    def setTxPort(self, txPort):
        self.output['tx']['port'] = txPort

    def setRxPort(self, rxPort):
        self.output['rx']['port'] = rxPort

    def setTxTotalPackets(self, tPackets):
        self.output['tx']['total_packets'] = tPackets

    def setRxTotalPackets(self, tPackets):
        self.output['rx']['total_packets'] = tPackets

    def setTxDuration(self, duration):
        self.output['tx']['duration'] = duration

    def setRequestedTxRate(self, rate):   
        self.output['tx']['requested_tx_rate'] = rate

    def setWarnings(self, warn):
        self.output['warnings'] = warn

    def getTxPort(self):
        return self.output['tx']['port']

    def getRxPort(self, rxPort):
        return self.output['rx']['port']

    def getTxTotalPackets(self):
        return self.output['tx']['total_packets']

    def getRxTotalPackets(self):
        return self.output['rx']['total_packets']

    def getTxDuration(self):
        return self.output['tx']['duration']

    def getRequestedTxRate(self):
        return self.output['tx']['requested_tx_rate'] 

    def getWarnings(self):
        return self.output['warnings']

    def toDictionary(self):
        return self.output

    def toString(self):
        return str(self.output)

class TrexDriver():

    # Builds an instance of TrexDriver
    def __init__(self, server, txPort, rxPort, pcap, rate, duration):
        self.server = server
        self.txPort = txPort
        self.rxPort = rxPort
        self.pcap = pcap
        self.rate = rate
        self.duration = duration

    # It creates a stream by leveraging the 'pcap' file which has been set 
    # during the driver creation.
    def __buildStreamsFromPcap(self):
        reader = dpkt.pcap.Reader(open(self.pcap, "rb"))
        streams = []
        for ts, pkt in reader:
            new_stream = STLStream(packet = STLPktBuilder(pkt_buffer=pkt), mode=STLTXCont())
            streams.append(new_stream)
        return streams

    def run(self):
        tOutput = TrexOutput()
        tOutput.setTxPort(self.txPort)
        tOutput.setRxPort(self.rxPort)
        tOutput.setRequestedTxRate(self.rate)
        tOutput.setTxDuration(self.duration)

        # We create the client
        client = STLClient(server=self.server)

        try:
            profile = None
            stream = None
            txStats = None
            rxStats = None
            allPorts = [self.txPort, self.rxPort]

            client.connect()

            # For safety reasons we reset any counter.
            client.reset(ports=allPorts)

            # We retrieve the streams
            # NOTE: we have as many streams as captured packets within 
            # the .pcap file.
            streams = self.__buildStreamsFromPcap()

            # We use only one port to multiplex altogether streams.
            client.add_streams(streams, ports=[self.txPort])

            # Even if we create a new client it is better to reset also
            # ports and streams, because between client creation and
            # start of the experiment some packets may be received on ports.
            client.clear_stats()

            client.start(ports=[self.txPort], mult=self.rate,
                         duration=self.duration)

            # Now we block until all packets have been sent/received. To
            # for be sure operations had been completed we wait for both
            # txPort and rxPort.
            client.wait_on_traffic(ports=allPorts)

            # We store warnings inside the dictionary in order to allow them
            # to be accessed afterwards
            warn = client.get_warnings()
            if warn:
                tOutput.setWarnings(warn)

            # We wait for a bit in order to let the counters be stable
            sleep(1)

            # We retrieve statistics from Tx and Rx ports.
            txStats = client.get_xstats(self.txPort)
            rxStats = client.get_xstats(self.rxPort)

            print(txStats)
            print("\n\n\n\n")
            # print(rxStats)
            tOutput.setTxTotalPackets(txStats['tx_good_packets'])
            tOutput.setRxTotalPackets(rxStats['rx_good_packets'])

        except STLError as e:
            traceback.print_exc()
            print(e)
            # sys.exit(1)
        except Exception as e:
            traceback.print_exc()
            print(e)

        finally:
            client.disconnect()

        return tOutput

# Entry point used for testing
if __name__ == '__main__':

    driver = TrexDriver('127.0.0.1', 0, 1, 'pcap/trex-pcap-files/srv6-init_request_a.pcap_replicated_8.pcap', '100%', 20)
    output = driver.run()
    print(output.toString())
