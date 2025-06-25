import socket
import time
import random
import threading
import os
import json
from collections import defaultdict

class ModbusFuzzer:
    def __init__(self, target_ip, target_port=502, restart_callback=None):
        self.target_ip = target_ip
        self.target_port = target_port
        self.restart_server = restart_callback or self.default_restart
        self.running = False
        self.start_time = 0
        self.report_times = [3600, 21600, 43200, 86400]  # 1h, 6h, 12h, 24h
        
        # Metrics tracking
        self.metrics = {
            'start_time': None,
            'packets_sent': 0,
            'crashes': 0,
            'unexpected_responses': 0,
            'function_codes_tested': set(),
            'field_mutations': defaultdict(int),
            'crash_log': [],
            'response_log': []
        }
        
        # Protocol knowledge base
        self.VALID_FUNCTION_CODES = set(range(1, 128))
        self.EXCEPTION_OFFSET = 0x80
        self.MBAP_HEADER_LEN = 7
        
        # Fuzzing parameters
        self.MUTATION_PROBABILITIES = {
            'unit_id': 0.3,
            'function_code': 0.4,
            'transaction_id': 0.2,
            'protocol_id': 0.1,
            'data': 0.8
        }
        self.TIMEOUT = 2.0  # Response timeout in seconds
        self.RECONNECT_ATTEMPTS = 5
        self.RECONNECT_DELAY = 10  # Seconds between reconnect attempts

    def default_restart(self):
        """Placeholder for server restart logic"""
        print("Implement server restart logic here")
        time.sleep(30)
        return True

    def build_modbus_frame(self, function_code, data=b'', unit_id=1):
        """Construct Modbus TCP frame with optional mutations"""
        transaction_id = random.randint(0, 65535).to_bytes(2, 'big')
        protocol_id = b'\x00\x00'  # Standard Modbus protocol identifier
        length = (len(data) + 2).to_bytes(2, 'big')  # +2 for unit_id + function_code
        
        return b''.join([
            transaction_id,
            protocol_id,
            length,
            bytes([unit_id]),
            bytes([function_code]),
            data
        ])

    def mutate_frame(self, frame):
        """Apply intelligent mutations to Modbus frame"""
        mutations = []
        frame = bytearray(frame)
        
        # Mutate Unit ID (1 byte)
        if random.random() < self.MUTATION_PROBABILITIES['unit_id']:
            frame[6] = random.randint(0, 255)
            mutations.append('unit_id')
            self.metrics['field_mutations']['unit_id'] += 1
        
        # Mutate Function Code (1 byte)
        if random.random() < self.MUTATION_PROBABILITIES['function_code']:
            frame[7] = random.choice([
                *self.VALID_FUNCTION_CODES,  # Valid codes
                *[x for x in range(256) if x not in self.VALID_FUNCTION_CODES]  # Invalid codes
            ])
            mutations.append('function_code')
            self.metrics['field_mutations']['function_code'] += 1
            self.metrics['function_codes_tested'].add(frame[7])
        
        # Mutate Transaction ID (2 bytes)
        if random.random() < self.MUTATION_PROBABILITIES['transaction_id']:
            frame[0:2] = random.randint(0, 65535).to_bytes(2, 'big')
            mutations.append('transaction_id')
            self.metrics['field_mutations']['transaction_id'] += 1
        
        # Mutate Protocol ID (2 bytes)
        if random.random() < self.MUTATION_PROBABILITIES['protocol_id']:
            frame[2:4] = random.randint(0, 65535).to_bytes(2, 'big')
            mutations.append('protocol_id')
            self.metrics['field_mutations']['protocol_id'] += 1
        
        # Mutate Data (variable length)
        if len(frame) > 8 and random.random() < self.MUTATION_PROBABILITIES['data']:
            self.mutate_data_section(frame[8:])
            mutations.append('data')
            self.metrics['field_mutations']['data'] += 1
        
        return bytes(frame), mutations

    def mutate_data_section(self, data):
        """Apply focused mutations to data section"""
        if not data:
            return
        
        mutation_type = random.choice([
            'bit_flip', 'byte_flip', 'insert_null',
            'max_value', 'min_value', 'random_block'
        ])
        
        if mutation_type == 'bit_flip':
            byte_pos = random.randint(0, len(data) - 1)
            bit_pos = random.randint(0, 7)
            data[byte_pos] ^= (1 << bit_pos)
        
        elif mutation_type == 'byte_flip':
            byte_pos = random.randint(0, len(data) - 1)
            data[byte_pos] = random.randint(0, 255)
        
        elif mutation_type == 'insert_null':
            if len(data) < 256:  # Prevent excessive growth
                insert_pos = random.randint(0, len(data))
                data[insert_pos:insert_pos] = b'\x00'
        
        elif mutation_type == 'max_value':
            byte_pos = random.randint(0, len(data) - 1)
            data[byte_pos] = 0xFF
        
        elif mutation_type == 'min_value':
            byte_pos = random.randint(0, len(data) - 1)
            data[byte_pos] = 0x00
        
        elif mutation_type == 'random_block':
            start = random.randint(0, len(data) - 1)
            end = random.randint(start, len(data))
            data[start:end] = os.urandom(end - start)

    def validate_response(self, request, response):
        """Determine if response is unexpected based on Modbus spec"""
        if not response:
            return False  # Timeout handled separately
        
        # Minimum response length validation
        if len(response) < self.MBAP_HEADER_LEN + 2:
            return True  # Unexpected (invalid structure)
        
        # Protocol identifier validation
        if response[2:4] != b'\x00\x00':
            return True  # Unexpected (non-Modbus protocol)
        
        # Length field consistency
        length = int.from_bytes(response[4:6], 'big')
        if len(response) - 6 != length:
            return True  # Unexpected (length mismatch)
        
        # Function code validation
        req_function_code = request[7]
        res_function_code = response[7]
        
        if res_function_code == req_function_code:
            return False  # Normal response
        
        if res_function_code == (req_function_code | self.EXCEPTION_OFFSET):
            # Exception response should have 1 additional byte
            return length != 3 or len(response) != self.MBAP_HEADER_LEN + 3
        
        return True  # Unexpected function code

    def fuzz_worker(self):
        """Main fuzzing execution thread"""
        self.metrics['start_time'] = time.time()
        
        while self.running:
            try:
                # Create connection
                sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
                sock.settimeout(self.TIMEOUT)
                sock.connect((self.target_ip, self.target_port))
                
                while self.running:
                    # Generate and mutate frame
                    function_code = random.choice([
                        *self.VALID_FUNCTION_CODES,
                        random.randint(0, 255)
                    ])
                    base_frame = self.build_modbus_frame(function_code, os.urandom(random.randint(0, 252)))
                    fuzzed_frame, mutations = self.mutate_frame(base_frame)
                    
                    # Track function code
                    self.metrics['function_codes_tested'].add(fuzzed_frame[7])
                    
                    # Send fuzzed frame
                    send_time = time.time()
                    sock.sendall(fuzzed_frame)
                    self.metrics['packets_sent'] += 1
                    
                    # Receive response
                    try:
                        response = sock.recv(1024)
                        if self.validate_response(fuzzed_frame, response):
                            self.metrics['unexpected_responses'] += 1
                            self.metrics['response_log'].append({
                                'timestamp': send_time,
                                'request': fuzzed_frame.hex(),
                                'response': response.hex() if response else None
                            })
                    except socket.timeout:
                        response = None
                    
                    # Check report triggers
                    elapsed = time.time() - self.metrics['start_time']
                    if any(rt <= elapsed for rt in self.report_times):
                        self.generate_report()
                        self.report_times = [rt for rt in self.report_times if rt > elapsed]
            
            except (socket.error, ConnectionResetError) as e:
                # Handle connection errors and potential crashes
                crash_time = time.time()
                self.metrics['crashes'] += 1
                self.metrics['crash_log'].append({
                    'timestamp': crash_time,
                    'packet': fuzzed_frame.hex(),
                    'error': str(e)
                })
                
                # Attempt server restart
                for _ in range(self.RECONNECT_ATTEMPTS):
                    if self.restart_server():
                        time.sleep(self.RECONNECT_DELAY)
                        break
                else:
                    self.running = False
                    print("Fatal error: Server restart failed")
            
            finally:
                try:
                    sock.close()
                except:
                    pass

    def generate_report(self):
        """Generate comprehensive test report"""
        elapsed = time.time() - self.metrics['start_time']
        hours = max(1, elapsed / 3600)
        
        report = {
            'timestamp': time.time(),
            'test_duration': elapsed,
            'function_code_coverage': len(self.metrics['function_codes_tested']),
            'field_mutation_coverage': len(self.metrics['field_mutations']),
            'crash_number': self.metrics['crashes'],
            'crash_per_hour': self.metrics['crashes'] / hours,
            'execution_speed': self.metrics['packets_sent'] / elapsed,
            'crash_packet_ratio': (
                self.metrics['crashes'] / self.metrics['packets_sent']
                if self.metrics['packets_sent'] else 0
            ),
            'unexpected_responses': self.metrics['unexpected_responses'],
            'unexpected_per_hour': self.metrics['unexpected_responses'] / hours,
            'unexpected_packet_ratio': (
                self.metrics['unexpected_responses'] / self.metrics['packets_sent']
                if self.metrics['packets_sent'] else 0
            ),
            'details': {
                'function_codes_tested': list(self.metrics['function_codes_tested']),
                'field_mutations': dict(self.metrics['field_mutations'])
            }
        }
        
        # Save report to file
        filename = f"modbus_fuzz_report_{int(time.time())}.json"
        with open(filename, 'w') as f:
            json.dump(report, f, indent=2)
        
        return report

    def start(self, duration=86400):  # 24 hours
        """Start fuzzing test"""
        self.running = True
        self.start_time = time.time()
        
        # Start watchdog thread
        threading.Thread(target=self.fuzz_worker, daemon=True).start()
        
        # Wait for test duration
        while time.time() - self.start_time < duration and self.running:
            time.sleep(1)
        
        self.running = False
        self.generate_report()  # Final report

# Usage Example
if __name__ == "__main__":
    fuzzer = ModbusFuzzer(
        target_ip="192.168.1.100",
        restart_callback=lambda: os.system("sudo systemctl restart modbus-server")
    )
    fuzzer.start()
