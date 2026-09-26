import csv, statistics
from collections import defaultdict
import matplotlib.pyplot as plt

CSV = "data/perf_results.csv"
OUT_DIR = "data"


def load():
    by_n = defaultdict(list)
    with open(CSV) as f:
        for row in csv.DictReader(f):
            n = int(row["n"])
            by_n[n].append({
                "reg": float(row["avg_registration_ms"]),
                "batch": float(row["batch_ms"]),
                "verify": float(row["verify_ms"]),
                "tput": float(row["throughput_reg_per_sec"]),
            })
    return by_n


def main():
    by_n = load()
    ns = sorted(by_n.keys())

    def avg(n, key): return statistics.mean(x[key] for x in by_n[n])

    # graph 1: devices vs batch time
    plt.figure()
    plt.plot(ns, [avg(n, "batch") for n in ns], marker="o")
    plt.xlabel("Number of devices")
    plt.ylabel("Batch processing time (ms)")
    plt.title("Devices vs Batch Registration Time")
    plt.grid(True)
    plt.savefig(f"{OUT_DIR}/graph_batch.png", dpi=120, bbox_inches="tight")
    plt.close()

    # graph 2: devices vs verification latency
    plt.figure()
    plt.plot(ns, [avg(n, "verify") for n in ns], marker="o", color="green")
    plt.xlabel("Number of devices")
    plt.ylabel("Verification latency (ms)")
    plt.title("Devices vs Verification Latency")
    plt.grid(True)
    plt.savefig(f"{OUT_DIR}/graph_verify.png", dpi=120, bbox_inches="tight")
    plt.close()

    # graph 3: devices vs throughput
    plt.figure()
    plt.plot(ns, [avg(n, "tput") for n in ns], marker="o", color="orange")
    plt.xlabel("Number of devices")
    plt.ylabel("Throughput (registrations/sec)")
    plt.title("Devices vs Registration Throughput")
    plt.grid(True)
    plt.savefig(f"{OUT_DIR}/graph_throughput.png", dpi=120, bbox_inches="tight")
    plt.close()

    print("Graphs saved to", OUT_DIR)


if __name__ == "__main__":
    main()