import subprocess
import traceback
import sys
import signal
import time
import statistics
import select

# config
monitorInterface = "enp7s0" # interface to run packet capture on
ranEmulatorNode = "10.0.0.3" # node against which to determine baseline latency
registrationTarget = "0x42" # point at which to consider registration complete
numgNB = 6 # number of gnb to test
numUE = 100 # number of UE per gNB
rate = 400 # delay between registrations - per UE per gNB (primary measured variable)
delay = 1 # delay in seconds between gNB startups - to add variation

# variables
latencies = []
start_time = 0
print("Ascertaining network baseline latency")
ping = float(subprocess.Popen(["ping", ranEmulatorNode, "-c", "4", "-q"], stdout=subprocess.PIPE, stderr=subprocess.DEVNULL, text=True).stdout.readlines()[-1].split("/")[4])
print(f"Average RTT to ran-emulator node: {ping}ms")

command = ['tshark', '-i', monitorInterface, '-f', 'host 10.0.0.3 or host 10.0.0.4 or host 10.0.0.5 or host 10.0.0.6 or host 10.0.0.7 or host 10.0.0.8', '-o', 'nas-5gs.null_decipher:true', '-Y', 'sctp', '-T', 'fields', '-e', 'frame.time_relative', '-e', 'ngap.RAN_UE_NGAP_ID', '-e', 'ngap.AMF_UE_NGAP_ID', '-e', 'nas_5gs.sm.message_type', '-e', 'nas_5gs.mm.message_type', '-e', 'ngap.procedureCode', '-e', 'ip.src', '-e', 'ip.dst', '-e', '_ws.col.Info', '-l'] # https://github.com/netsys-edinburgh/nervion-powder/blob/master/config/test/a1_capture.sh
process = subprocess.Popen(command, stdout=subprocess.PIPE, stderr=subprocess.DEVNULL, text=True)
subprocess.run(f"ssh root@10.3 /root/pr_start.sh {numgNB} {numUE} {rate} {delay}", shell=True)
print("Starting analysis")
UEs={}
total = 0
total2 = 0

class UEStatistics:
    def __init__(self, id: int, registrationTime: float):
        self.id = id
        self.registrationTime = registrationTime
    def registrationSuccess(self, successTime: float, amfip):
        global total
        total += 1
        self.successTime = successTime
        self.timems = round(((self.successTime - self.registrationTime) * 1000), 5)
        self.tookTime = round(time.time() - start_time, 2)
        print(total, '{:.2f}'.format(self.tookTime), "Negotiation complete, PDU setup for", self.id, "from", amfip, "(took", self.timems, "ms)")
        latencies.append(round(((self.successTime - self.registrationTime) * 1000), 5))

def handleMessage(timestamp, ueid, type, amfip):
    if(type == "0x41"):
        UEs[f'{amfip} - {ueid}'] = UEStatistics(ueid, timestamp)
        signal.alarm(int(30)) # 30s timeout
    elif (type == registrationTarget):
        global total2
        total2 += 1
        if f'{amfip} - {ueid}' in UEs:
          UEs[f'{amfip} - {ueid}'].registrationSuccess(timestamp, amfip)
        signal.alarm(int(30)) # 30s timeout
    elif (type == "0x34"):
        print("Registration rejected - aborting test!")
        sys.exit(0)

def signal_handler(sig, frame):
    print("SUCCESS!")
    subprocess.run("ssh root@10.3 /root/pr_stop.sh", shell=True)
    print(f"Analysed {total2} connections (avg {round(len(latencies)/(time.time()-start_time),5)}/s)")
    print(f"min/avg/max {min(latencies)}/{round(sum(latencies[50:-50])/float(len(latencies)),5)}/{max(latencies)}") # drop first/last 50 to prevent staggered gNB starts skewing results
    sys.exit(0)

signal.signal(signal.SIGINT, signal_handler)
signal.signal(signal.SIGALRM, signal_handler)

for line in iter(process.stdout.readline, ''):
    try:
        if start_time == 0:
            start_time = time.time()
        split = line.split("\t")
        timestamp = float(split[0])
        src = split[6]
        dst = split[7]
        amfip = src if (src != "10.0.0.2") else dst
        num_messages = len(split[1].split(","))
        for i in range(0, num_messages):
            if (i < len(split[4].split(","))):
                handleMessage(timestamp,
                            split[1].split(",")[i], #UE ID
                            #split[2].split(",")[i],  #AMF ID
                            split[4].split(",")[i],  #Message type
                            amfip # Use IP instead, ID not reliable
                            )
    except Exception:
        print(UEs)
        print(traceback.format_exc())
        print(line.split("\t"))