import pyshark
import matplotlib.pyplot as plt

pcap = "tcp-wireshark-trace1-1.pcapng"   # updated extension

# Load pcapng using JSON parsing for better compatibility
cap = pyshark.FileCapture(
    pcap,
    display_filter="tcp",
    use_json=True,
    keep_packets=False
)

times = []
seqs = []

start_time = None

for pkt in cap:
    try:
        # Ensure packet has layers
        if "IP" not in pkt:
            continue

        src = pkt.ip.src
        dst = pkt.ip.dst

        # Filter: only client → UMass server
        # UMass Gaia: 128.119.x.x
        if not src.startswith("128.119."):
            continue

        # Extract timestamp + sequence numbers
        t = float(pkt.sniff_timestamp)
        seq = int(pkt.tcp.seq)

        if start_time is None:
            start_time = t

        times.append(t - start_time)
        seqs.append(seq)

    except Exception as e:
        # Print errors if needed for debugging
        pass

cap.close()

# Plot
plt.scatter(times, seqs, s=8)
plt.xlabel("Time (s)")
plt.ylabel("Sequence Number")
plt.title("TCP Time-Sequence Graph (Stevens Format)")
plt.tight_layout()
plt.savefig("stevens_graph.png")

print("Saved: stevens_graph.png")
