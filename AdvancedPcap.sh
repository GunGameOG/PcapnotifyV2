#!/bin/bash

# Set the interface to capture packets (e.g., eth0)
INTERFACE="your_network_interface"

# Set the output pcap file path
PCAP_FILE="/path/to/your/file.pcap"

# Set the temporary directory
TMP_DIR="/path/to/your/tmpdir"

# Set your webhook URL
WEBHOOK_URL="https://your.webhook.url"

# Set the threshold for packet count
THRESHOLD=10000

# Start capturing packets and save to the specified pcap file
tcpdump -i $INTERFACE -w $PCAP_FILE &

# Sleep for a short duration
sleep 30

# Stop capturing packets
pkill tcpdump

# Analyze the captured packets and extract source protocol, port, and IP
RESULTS=$(tshark -r $PCAP_FILE -T fields -e ip.proto -e ip.src -e tcp.srcport -e udp.srcport | sort | uniq -c)

# Check if any source IP exceeds the threshold
while read -r LINE; do
    COUNT=$(echo $LINE | awk '{print $1}')
    PROTOCOL=$(echo $LINE | awk '{print $2}')
    SRC_IP=$(echo $LINE | awk '{print $3}')
    SRC_PORT=$(echo $LINE | awk '{print $4}')

    if [ $COUNT -gt $THRESHOLD ]; then
        # Create a network graph using editcap and save as a PNG file
        editcap -F libpcap $PCAP_FILE $TMP_DIR/graph.pcap
        capinfos -g -i $TMP_DIR/graph.pcap -o $TMP_DIR/graph.png

        # Send notification or alert about potential DDoS attack with network graph
        MESSAGE="Potential DDoS attack detected from $SRC_IP using $PROTOCOL on source port $SRC_PORT. Packet count: $COUNT"
        curl -X POST -F "message=$MESSAGE" -F "image=@$TMP_DIR/graph.png" $WEBHOOK_URL
    fi
done <<< "$RESULTS"

# Clean up temporary files
rm -rf $TMP_DIR

# Clean up the pcap file
rm $PCAP_FILE
