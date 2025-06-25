import time
import random
import json
import threading
from pymodbus.client.sync import ModbusTcpClient
from pymodbus.exceptions import ModbusException
from datetime import datetime, timedelta

# Config
TARGET_IP = "192.168.0.100"
TARGET_PORT = 502
FUZZ_DURATION = 24 * 3600  # 24 hours
REPORT_INTERVALS = [1, 6, 12, 24]  # hours
LOG_FILE = "modbus_fuzz_log.json"

# Metrics
metrics = {
    "function_codes_tested": set(),
    "field_mutations": 0,
    "crashes": 0,
    "unexpected_responses": 0,
    "packets_sent": 0,
    "event_log": []
}

crash_lock = threading.Lock()
start_time = datetime.now()
report_times = [start_time + timedelta(hours=h) for h in REPORT_INTERVALS]

# Function Codes to test (complete set)
function_codes = list(range(1, 127))

# Helper: Save report
def save_report():
    now = datetime.now()
    elapsed_hours = (now - start_time).total_seconds() / 3600
    report = {
        "timestamp": now.isoformat(),
        "function_code_coverage": len(metrics["function_codes_tested"]),
        "field_mutation_coverage": metrics["field_mutations"],
        "crash_number": metrics["crashes"],
        "crash_per_hour": metrics["crashes"] / elapsed_hours if elapsed_hours else 0,
        "execution_speed": metrics["packets_sent"] / elapsed_hours if elapsed_hours else 0,
        "crash_packet_ratio": metrics["crashes"] / metrics["packets_sent"] if metrics["packets_sent"] else 0,
        "unexpected_response_number": metrics["unexpected_responses"],
        "unexpected_response_per_hour": metrics["unexpected_responses"] / elapsed_hours if elapsed_hours else 0,
        "unexpected_response_per_packet": metrics["unexpected_responses"] / metrics["packets_sent"] if metrics["packets_sent"] else 0
    }
    with open(f"report_{int(elapsed_hours)}h.json", 'w') as f:
        json.dump(report, f, indent=2)

# Fuzzing logic
client = ModbusTcpClient(TARGET_IP, port=TARGET_PORT)

try:
    while (datetime.now() - start_time).total_seconds() < FUZZ_DURATION:
        fc = random.choice(function_codes)
        metrics["function_codes_tested"].add(fc)
        address = random.randint(0, 65535)
        count = random.randint(1, 125)
        value = random.randint(0, 65535)
        metrics["field_mutations"] += 3
        
        try:
            # Use generic read/write based on function code class
            if fc in range(1, 5):
                response = client.read_coils(address, count, unit=1)
            elif fc in range(5, 7):
                response = client.write_coil(address, value & 1, unit=1)
            elif fc in range(15, 17):
                bits = [bool(random.getrandbits(1)) for _ in range(count)]
                response = client.write_coils(address, bits, unit=1)
            elif fc in range(3, 5):
                response = client.read_holding_registers(address, count, unit=1)
            else:
                response = client.execute(fc, address, count)

            metrics["packets_sent"] += 1

            # Handle unexpected response
            if not response or response.isError():
                metrics["unexpected_responses"] += 1
                with open("unexpected_response_packets.log", "a") as log:
                    log.write(f"{datetime.now().isoformat()} Unexpected response for FC {fc} address {address} count {count}\n")

        except ModbusException as e:
            with crash_lock:
                metrics["crashes"] += 1
                crash_event = {
                    "timestamp": datetime.now().isoformat(),
                    "function_code": fc,
                    "address": address,
                    "count": count,
                    "error": str(e)
                }
                metrics["event_log"].append(crash_event)
                with open("crashes.log", "a") as crash_log:
                    crash_log.write(json.dumps(crash_event) + "\n")

        # Periodic report
        now = datetime.now()
        if report_times and now >= report_times[0]:
            save_report()
            report_times.pop(0)

        time.sleep(0.01)  # pacing

finally:
    client.close()
    save_report()
    with open(LOG_FILE, 'w') as f:
        json.dump(metrics, f, indent=2)
