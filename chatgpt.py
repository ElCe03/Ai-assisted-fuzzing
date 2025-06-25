import socket
import struct
import random
import time
import json
import threading
from datetime import datetime, timedelta

# Configuration
MODBUS_IP = "192.168.0.100"  # Change as needed
MODBUS_PORT = 502            # Default Modbus TCP port
TEST_DURATION_HOURS = 24
REPORT_TIMES = [1, 6, 12, 24]  # in hours
PACKET_SEND_INTERVAL = 0.01   # Time between packets (can be adjusted)

# Metrics
metrics = {
    "function_codes_tested": set(),
    "field_mutation_coverage": 0,
    "crash_count": 0,
    "unexpected_response_count": 0,
    "total_packets_sent": 0,
    "crashes": [],
    "unexpected_responses": []
}

lock = threading.Lock()

# Modbus function codes to test (official + less common)
FUNCTION_CODES = list(range(1, 127))

# Mutation functions
def mutate_packet(fc):
    transaction_id = random.randint(0, 0xFFFF)
    protocol_id = 0
    unit_id = random.randint(0, 255)
    address = random.randint(0, 0xFFFF)
    quantity = random.randint(1, 125)
    
    # Payload building depending on FC
    payload = struct.pack('>BHH', fc, address, quantity)
    length = len(payload) + 1

    header = struct.pack('>HHHB', transaction_id, protocol_id, length, unit_id)
    pdu = bytes([fc]) + payload

    packet = header + pdu
    return packet, {
        "transaction_id": transaction_id,
        "unit_id": unit_id,
        "function_code": fc,
        "address": address,
        "quantity": quantity
    }

def send_packet(packet):
    try:
        with socket.create_connection((MODBUS_IP, MODBUS_PORT), timeout=2) as s:
            s.sendall(packet)
            response = s.recv(1024)
            return response
    except (socket.timeout, ConnectionResetError, ConnectionRefusedError):
        return None

def fuzzing_loop():
    start_time = time.time()
    end_time = start_time + TEST_DURATION_HOURS * 3600
    next_report = [start_time + h * 3600 for h in REPORT_TIMES]

    while time.time() < end_time:
        fc = random.choice(FUNCTION_CODES)
        packet, details = mutate_packet(fc)
        response = send_packet(packet)

        with lock:
            metrics["function_codes_tested"].add(fc)
            metrics["field_mutation_coverage"] += 1
            metrics["total_packets_sent"] += 1

            if response is None:
                metrics["crash_count"] += 1
                metrics["crashes"].append({"timestamp": datetime.now().isoformat(), "packet": details})
            elif response and (response[7] & 0x80):  # Error response
                metrics["unexpected_response_count"] += 1
                metrics["unexpected_responses"].append({"timestamp": datetime.now().isoformat(), "packet": details, "response": response.hex()})

        time.sleep(PACKET_SEND_INTERVAL)

        if next_report and time.time() >= next_report[0]:
            generate_report(REPORT_TIMES[len(REPORT_TIMES) - len(next_report)], start_time)
            next_report.pop(0)

    generate_report(24, start_time)

def generate_report(hour_mark, start_time):
    elapsed_time = (time.time() - start_time) / 3600
    with lock:
        report = {
            "timestamp": datetime.now().isoformat(),
            "hour_mark": hour_mark,
            "function_code_coverage": len(metrics["function_codes_tested"]),
            "field_mutation_coverage": metrics["field_mutation_coverage"],
            "crash_number": metrics["crash_count"],
            "crash_per_hour": metrics["crash_count"] / elapsed_time,
            "execution_speed": metrics["total_packets_sent"] / elapsed_time / 3600,
            "crash_per_packet": metrics["crash_count"] / metrics["total_packets_sent"] if metrics["total_packets_sent"] else 0,
            "unexpected_response_number": metrics["unexpected_response_count"],
            "unexpected_per_hour": metrics["unexpected_response_count"] / elapsed_time,
            "unexpected_per_packet": metrics["unexpected_response_count"] / metrics["total_packets_sent"] if metrics["total_packets_sent"] else 0,
        }
        with open(f"modbus_fuzzing_report_{hour_mark}h.json", "w") as f:
            json.dump(report, f, indent=2)
        print(f"[+] Report for hour {hour_mark} written.")

if __name__ == "__main__":
    fuzzing_thread = threading.Thread(target=fuzzing_loop)
    fuzzing_thread.start()
    fuzzing_thread.join()
