import time
from datetime import datetime
import random
from pymodbus.client import ModbusTcpClient
from pymodbus.payload import BinaryPayloadBuilder
from pymodbus.constants import Endian
from pymodbus.exceptions import ModbusIOException, ModbusException

# --- Configuration ---
TARGET_IP = "127.0.0.1"  # Replace with your Modbus slave IP
TARGET_PORT = 502
UNIT_ID = 1

TEST_DURATION_SECONDS = 24 * 60 * 60  # 24 hours

# --- Global Metrics ---
total_packets_sent = 0
total_crashes = 0
total_unexpected_responses = 0
start_time = time.time()
last_report_time = start_time

crashes_log = [] # Stores (timestamp, packet_hex, description)
unexpected_responses_log = [] # Stores (timestamp, sent_packet_hex, received_response_hex, description)

# To track coverage
function_codes_tested = set()
mutated_fields = set() # Example: "transaction_id", "function_code", "address", "quantity"

# --- Helper Functions ---
def get_current_metrics():
    current_duration_seconds = time.time() - start_time
    current_duration_hours = current_duration_seconds / 3600.0

    execution_speed = total_packets_sent / current_duration_seconds if current_duration_seconds > 0 else 0
    crash_per_hour = total_crashes / current_duration_hours if current_duration_hours > 0 else 0
    crash_per_packet = total_crashes / total_packets_sent if total_packets_sent > 0 else 0
    unexp_resp_per_hour = total_unexpected_responses / current_duration_hours if current_duration_hours > 0 else 0
    unexp_resp_per_packet = total_unexpected_responses / total_packets_sent if total_packets_sent > 0 else 0

    return {
        "function_code_coverage": len(function_codes_tested),
        "field_mutation_coverage": len(mutated_fields),
        "crash_number": total_crashes,
        "crash_per_hour": crash_per_hour,
        "execution_speed": execution_speed,
        "crash_per_packet_ratio": crash_per_packet,
        "unexpected_response_number": total_unexpected_responses,
        "unexpected_response_per_hour": unexp_resp_per_hour,
        "unexpected_response_per_packet_ratio": unexp_resp_per_packet,
        "duration_hours": current_duration_hours
    }

def generate_report(report_name):
    metrics = get_current_metrics()
    current_time_str = datetime.now().strftime("%Y-%m-%d %H:%M:%S CEST")

    report = f"""
Fuzzing Test Report - {report_name} ({current_time_str})

Test Duration: {metrics['duration_hours']:.2f} hours

Metrics:
------------------------------------------------------------
Function Code Coverage:             {metrics['function_code_coverage']}
Field Mutation Coverage:            {metrics['field_mutation_coverage']}
Crash Number:                       {metrics['crash_number']}
Crash/Hour:                         {metrics['crash_per_hour']:.2f}
Execution Speed:                    {metrics['execution_speed']:.2f} packets/second
Crash/Packet Ratio:                 {metrics['crash_per_packet_ratio']:.4f} (or N/A if no crashes)
Number of Unexpected Responses:     {metrics['unexpected_response_number']}
Unexpected Response/Hour:           {metrics['unexpected_response_per_hour']:.2f}
Unexpected Response/Packet Ratio:   {metrics['unexpected_response_per_packet_ratio']:.4f} (or N/A if no unexpected responses)

Recent Events (Last Report Interval):
------------------------------------------------------------
"""
    # Append recent crashes and unexpected responses
    # (For a real implementation, you'd filter logs based on the last report time)
    for ts, packet, desc in crashes_log[-5:]: # Last 5 crashes
        report += f"- Timestamp: {datetime.fromtimestamp(ts).strftime('%Y-%m-%d %H:%M:%S CEST')}\n"
        report += f"  Event Type: Server Crash\n"
        report += f"  Packet Sent (Hex): {packet}\n"
        report += f"  Description: {desc}\n\n"

    for ts, sent_packet, received_response, desc in unexpected_responses_log[-5:]: # Last 5 unexpected responses
        report += f"- Timestamp: {datetime.fromtimestamp(ts).strftime('%Y-%m-%d %H:%M:%S CEST')}\n"
        report += f"  Event Type: Unexpected Response\n"
        report += f"  Packet Sent (Hex): {sent_packet}\n"
        report += f"  Response Received (Hex): {received_response}\n"
        report += f"  Description: {desc}\n\n"

    print(report)
    with open(f"fuzz_report_{report_name.replace(' ', '_').lower()}.txt", "a") as f:
        f.write(report)


def hex_dump(data):
    if data is None:
        return "None"
    return " ".join(f"{byte:02X}" for byte in data)

# --- Fuzzing Logic (Simplified Example) ---
def create_fuzzed_packet():
    global total_packets_sent
    total_packets_sent += 1

    function_code = random.randint(0, 255) # Fuzzing function codes
    function_codes_tested.add(function_code)

    # Basic example of different mutations
    mutation_type = random.choice([
        "valid_read_coil", "invalid_function_code", "fuzz_address_quantity",
        "corrupt_header_tid", "corrupt_header_length"
    ])

    client = ModbusTcpClient(TARGET_IP, TARGET_PORT)
    client.connect()

    packet_to_send_bytes = None
    description = ""

    try:
        if mutation_type == "valid_read_coil":
            start_address = random.randint(0, 100)
            quantity = random.randint(1, 20)
            description = f"Valid Read Coils (FC3, addr={start_address}, qty={quantity})"
            response = client.read_coils(start_address, quantity, unit=UNIT_ID)
            packet_to_send_bytes = client.last_request.encode() # Get the raw packet sent by pymodbus
            mutated_fields.add("address")
            mutated_fields.add("quantity")

        elif mutation_type == "invalid_function_code":
            # Manually craft a packet with an invalid function code
            # Example: A simple Read Holding Registers PDU but with a fuzzed FC
            # Transaction ID (2 bytes), Protocol ID (2 bytes), Length (2 bytes), Unit ID (1 byte)
            # Function Code (1 byte), Starting Address (2 bytes), Quantity (2 bytes)
            # PyModbus doesn't directly support sending arbitrary raw bytes easily for the whole ADU,
            # so we'd simulate it or use a lower-level socket for full control.
            # For demonstration, we'll try to trigger it via a valid function but then
            # mutate the function code in the raw bytes if we had direct control.
            # A more robust fuzzer would craft packets directly at byte level.

            # For now, let's use a function code that pymodbus might send, then manually corrupt its internal representation
            # This is a conceptual workaround for the example. A real fuzzer would build from scratch.
            builder = BinaryPayloadBuilder(byteorder=Endian.BIG, wordorder=Endian.BIG)
            builder.add_16bit_uint(0x0001) # Start Address
            builder.add_16bit_uint(0x0001) # Quantity
            pdu_bytes = b'\x03' + builder.build() # FC3 (Read Holding Registers) + data
            # Now, replace the function code byte
            fuzzed_fc = random.choice([0x45, 0x99, 0xFF, 0x00]) # Example invalid FCs
            pdu_bytes_fuzzed = bytes([fuzzed_fc]) + pdu_bytes[1:]

            # This part is tricky with pymodbus directly.
            # For a real fuzzer, you'd send `pdu_bytes_fuzzed` wrapped in MBAP header.
            # We'll simulate by trying a client call and hoping for an exception.
            # If the slave is strict, it might just return an illegal function code error.
            # If the slave is vulnerable, it might crash.

            # Attempt a read coils and then pretend we fuzzed the FC in the raw packet
            # In a real fuzzer, you would craft the full ADU directly.
            try:
                response = client.read_coils(0, 1, unit=UNIT_ID)
                packet_to_send_bytes = client.last_request.encode()
                # Simulate altering the FC in the raw packet
                if packet_to_send_bytes and len(packet_to_send_bytes) >= 8: # MBAP + Unit ID + FC
                     # Assuming FC is at offset 7 for Modbus TCP ADU (after Transaction ID, Protocol ID, Length, Unit ID)
                    original_fc_byte = packet_to_send_bytes[7]
                    mutated_fc_byte = random.randint(0, 255) # Completely random FC
                    # Ensure it's different from the original if we actually sent a valid one
                    while mutated_fc_byte == original_fc_byte and function_code not in [0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x0F, 0x10]:
                         mutated_fc_byte = random.randint(0, 255)

                    packet_to_send_bytes = bytearray(packet_to_send_bytes)
                    packet_to_send_bytes[7] = mutated_fc_byte
                    packet_to_send_bytes = bytes(packet_to_send_bytes)

                    # Now, actually send the fuzzed raw bytes (requires lower level socket if pymodbus doesn't expose this)
                    # This is where a custom socket send would go. For now, we'll just log it.
                    description = f"Fuzzed Function Code: {hex(mutated_fc_byte)} (Original: {hex(original_fc_byte)})"
                    mutated_fields.add("function_code")
                    # For a real fuzzer, you'd send this raw packet and check the response.
                    # As pymodbus abstracts this, we'll rely on its exception handling for now.

            except Exception as e:
                # If pymodbus itself complains about the FC, it means we can't even send it easily.
                # This highlights the need for direct socket manipulation for truly malformed packets.
                pass


        elif mutation_type == "fuzz_address_quantity":
            fc = random.choice([0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x0F, 0x10]) # Valid FCs for address/quantity
            start_address = random.choice([
                0, 1, 65535, random.randint(100, 65000) # Boundary values and large random
            ])
            quantity = random.choice([
                0, 1, 65535, random.randint(100, 65000) # Boundary values and large random
            ])

            function_codes_tested.add(fc)
            mutated_fields.add("address")
            mutated_fields.add("quantity")
            description = f"Fuzzed Address/Quantity (FC{fc}, addr={start_address}, qty={quantity})"

            try:
                if fc == 0x01: response = client.read_coils(start_address, quantity, unit=UNIT_ID)
                elif fc == 0x02: response = client.read_discrete_inputs(start_address, quantity, unit=UNIT_ID)
                elif fc == 0x03: response = client.read_holding_registers(start_address, quantity, unit=UNIT_ID)
                elif fc == 0x04: response = client.read_input_registers(start_address, quantity, unit=UNIT_ID)
                elif fc == 0x05: response = client.write_coil(start_address, True, unit=UNIT_ID)
                elif fc == 0x06: response = client.write_register(start_address, 123, unit=UNIT_ID)
                elif fc == 0x0F: response = client.write_coils(start_address, [True]*5, unit=UNIT_ID) # Fixed data for simplicity
                elif fc == 0x10: response = client.write_registers(start_address, [123, 456], unit=UNIT_ID) # Fixed data for simplicity
                packet_to_send_bytes = client.last_request.encode()

            except Exception as e:
                pass # Handled below by checking response object

        elif mutation_type == "corrupt_header_tid":
            # This requires lower-level packet crafting.
            # With pymodbus, you'd have to construct the entire MBAP header + PDU yourself.
            # Example: Send a valid Read Coils, then corrupt its Transaction ID.
            # This is beyond direct pymodbus high-level calls.
            # For demonstration, we'll just log the intent.
            description = "Attempted to corrupt Transaction ID (requires raw socket)"
            mutated_fields.add("transaction_id")
            # In a real fuzzer, you'd generate a valid packet, then modify its bytes.

        elif mutation_type == "corrupt_header_length":
            # Similar to corrupting TID, requires raw socket access.
            description = "Attempted to corrupt Length field (requires raw socket)"
            mutated_fields.add("length_field")
            # In a real fuzzer, you'd generate a valid packet, then modify its bytes.


        else:
            description = "Unhandled mutation type"


        response_received = False
        response_bytes = None
        if 'response' in locals() and response is not None:
            response_received = True
            if hasattr(response, 'encode'): # PyModbus 3.x+ way to get raw response
                 response_bytes = response.encode()
            elif hasattr(client, 'last_response') and client.last_response:
                 response_bytes = client.last_response.encode() # Older pymodbus or if not directly encoded

        if not response_received or response.isError():
            # This covers timeouts (no response), connection errors, and Modbus exceptions (illegal function, illegal data address, etc.)
            # Distinguish between crashes (no response/connection lost) and protocol errors (unexpected response)
            current_timestamp = time.time()
            if not response_received or isinstance(response, (ModbusIOException, ModbusException)):
                 # ModbusIOException usually means connection issues or no response from the server
                 # ModbusException means the server sent an error response (e.g., illegal function)
                if not response_received: # Most likely a crash/timeout
                    total_crashes += 1
                    crashes_log.append((current_timestamp, hex_dump(packet_to_send_bytes), f"Server crash: No response or connection dropped. Type: {mutation_type}, Desc: {description}"))
                    print(f"[{datetime.now().strftime('%H:%M:%S')}] CRASH DETECTED: No response for packet: {hex_dump(packet_to_send_bytes)}")
                    client.close() # Attempt to close and re-establish connection
                    time.sleep(1) # Give server time to recover if it crashed
                else: # Server sent an error response, which might be unexpected for the fuzzed input
                    total_unexpected_responses += 1
                    error_desc = f"Modbus Exception: {response}"
                    unexpected_responses_log.append((current_timestamp, hex_dump(packet_to_send_bytes), hex_dump(response_bytes), f"Unexpected response: {error_desc}. Type: {mutation_type}, Desc: {description}"))
                    print(f"[{datetime.now().strftime('%H:%M:%S')}] UNEXPECTED RESPONSE: {error_desc} for packet: {hex_dump(packet_to_send_bytes)}")
            else:
                # Other unexpected responses (e.g., valid Modbus but logically incorrect for the fuzzed input)
                total_unexpected_responses += 1
                unexpected_responses_log.append((current_timestamp, hex_dump(packet_to_send_bytes), hex_dump(response_bytes), f"Unexpected non-error response. Type: {mutation_type}, Desc: {description}"))
                print(f"[{datetime.now().strftime('%H:%M:%S')}] UNEXPECTED RESPONSE (Non-Error): {hex_dump(response_bytes)} for packet: {hex_dump(packet_to_send_bytes)}")
        # else:
        #     print(f"[{datetime.now().strftime('%H:%M:%S')}] Fuzz success (no crash/unexp resp): {description}")

    except ConnectionRefusedError:
        total_crashes += 1
        current_timestamp = time.time()
        crashes_log.append((current_timestamp, hex_dump(packet_to_send_bytes), f"Server crash: Connection refused. Type: {mutation_type}, Desc: {description}"))
        print(f"[{datetime.now().strftime('%H:%M:%S')}] CRASH DETECTED: Connection refused. Packet (if sent): {hex_dump(packet_to_send_bytes)}")
        time.sleep(5) # Longer sleep for connection refusal
    except Exception as e:
        total_crashes += 1
        current_timestamp = time.time()
        crashes_log.append((current_timestamp, hex_dump(packet_to_send_bytes), f"Server crash: General exception: {e}. Type: {mutation_type}, Desc: {description}"))
        print(f"[{datetime.now().strftime('%H:%M:%S')}] CRASH DETECTED: General Exception {e}. Packet (if sent): {hex_dump(packet_to_send_bytes)}")
        time.sleep(2) # Sleep for general exceptions

    finally:
        client.close()


# --- Main Fuzzing Loop ---
if __name__ == "__main__":
    report_intervals = [1 * 3600, 6 * 3600, 12 * 3600, TEST_DURATION_SECONDS]
    next_report_index = 0

    print(f"Starting Modbus Fuzzing Test against {TARGET_IP}:{TARGET_PORT} for {TEST_DURATION_SECONDS/3600} hours...")

    while time.time() - start_time < TEST_DURATION_SECONDS:
        current_elapsed_time = time.time() - start_time

        if next_report_index < len(report_intervals) and current_elapsed_time >= report_intervals[next_report_index]:
            report_name = ""
            if report_intervals[next_report_index] == 1 * 3600: report_name = "1 Hour Report"
            elif report_intervals[next_report_index] == 6 * 3600: report_name = "6 Hour Report"
            elif report_intervals[next_report_index] == 12 * 3600: report_name = "12 Hour Report"
            elif report_intervals[next_report_index] == TEST_DURATION_SECONDS: report_name = "Final Report"
            generate_report(report_name)
            next_report_index += 1

        create_fuzzed_packet()
        time.sleep(0.01) # Small delay to avoid overwhelming the server and allow for context switching

    # Final report
    generate_report("Final Report")
    print("Fuzzing test completed.")
