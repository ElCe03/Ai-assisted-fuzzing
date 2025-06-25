import random
import time
import socket
import struct
from datetime import datetime
import json
import logging
from collections import defaultdict

class ModbusFuzzer:
    def __init__(self, target_ip, target_port=502):
        self.target_ip = target_ip
        self.target_port = target_port
        self.start_time = time.time()
        self.stats = {
            'start_time': datetime.now().isoformat(),
            'packets_sent': 0,
            'crashes': 0,
            'unexpected_responses': 0,
            'function_codes_tested': set(),
            'fields_mutated': defaultdict(int),
            'crash_packets': [],
            'unexpected_response_packets': []
        }
        self.logger = self._setup_logger()
        
        # Modbus protocol knowledge base
        self.function_codes = {
            'read': [1, 2, 3, 4],
            'write': [5, 6, 15, 16, 22, 23],
            'diagnostic': [8],
            'other': [7, 11, 12, 17, 20, 21, 24, 43]
        }
        self.max_registers = 125  # Modbus protocol limit for most functions
        self.max_coils = 2000     # Practical limit for coils

    def _setup_logger(self):
        logger = logging.getLogger('ModbusFuzzer')
        logger.setLevel(logging.INFO)
        handler = logging.FileHandler('modbus_fuzzer.log')
        formatter = logging.Formatter('%(asctime)s - %(levelname)s - %(message)s')
        handler.setFormatter(formatter)
        logger.addHandler(handler)
        return logger

    def generate_fuzzed_packet(self):
        """Generate a fuzzed Modbus packet with intelligent mutations"""
        # Randomly select a function code
        category = random.choice(list(self.function_codes.keys()))
        func_code = random.choice(self.function_codes[category])
        self.stats['function_codes_tested'].add(func_code)
        
        # Generate transaction ID (0-65535)
        trans_id = random.randint(0, 65535)
        
        # Protocol ID (0 for Modbus/TCP)
        protocol_id = 0
        
        # Unit identifier (typically 1 for serial, 0-255 for TCP)
        unit_id = random.randint(0, 255)
        
        # Create base header
        header = struct.pack('>HHHB', trans_id, protocol_id, 0, unit_id)  # Length will be updated later
        
        # Function-specific payload generation with fuzzing
        payload = b''
        fields_mutated = []
        
        if func_code in [1, 2, 3, 4]:  # Read functions
            # Random address (0-65535)
            address = random.randint(0, 65535)
            fields_mutated.append('address')
            
            # Random quantity with some chance to exceed limits
            if random.random() < 0.3:  # 30% chance to fuzz quantity
                quantity = random.randint(0, 65535)
            else:
                max_qty = self.max_coils if func_code in [1, 2] else self.max_registers
                quantity = random.randint(1, max_qty)
            fields_mutated.append('quantity')
            
            payload = struct.pack('>BHH', func_code, address, quantity)
            
        elif func_code in [5, 6, 15, 16]:  # Write functions
            address = random.randint(0, 65535)
            fields_mutated.append('address')
            
            if func_code in [5, 6]:  # Single write
                value = random.randint(0, 65535)
                fields_mutated.append('value')
                payload = struct.pack('>BHH', func_code, address, value)
            else:  # Multiple write
                quantity = random.randint(1, self.max_registers if func_code == 16 else self.max_coils)
                fields_mutated.append('quantity')
                
                if random.random() < 0.2:  # 20% chance to fuzz byte count
                    byte_count = random.randint(0, 255)
                else:
                    byte_count = quantity // 8 + (1 if quantity % 8 else 0) if func_code == 15 else quantity * 2
                fields_mutated.append('byte_count')
                
                values = bytes([random.randint(0, 255) for _ in range(byte_count)])
                fields_mutated.append('values')
                payload = struct.pack('>BHHB', func_code, address, quantity, byte_count) + values
                
        elif func_code == 8:  # Diagnostics
            sub_func = random.randint(0, 65535)
            fields_mutated.append('sub_function')
            data = random.randint(0, 65535)
            fields_mutated.append('data')
            payload = struct.pack('>BHH', func_code, sub_func, data)
            
        else:  # Other functions - generic fuzzing
            # Generate random payload of random length (1-252 bytes)
            payload_length = random.randint(1, 252)
            payload = struct.pack('>B', func_code) + bytes([random.randint(0, 255) for _ in range(payload_length)])
            fields_mutated.extend(['random_payload'])
        
        # Update fields mutated count
        for field in fields_mutated:
            self.stats['fields_mutated'][field] += 1
        
        # Update length field in header (unit ID + payload)
        length = len(payload) + 1  # +1 for unit ID
        header = header[:4] + struct.pack('>H', length) + header[6:]
        
        return header + payload

    def send_packet(self, packet):
        """Send packet to target and get response"""
        try:
            with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
                s.settimeout(2.0)  # 2 second timeout
                s.connect((self.target_ip, self.target_port))
                s.sendall(packet)
                
                # Try to get response (Modbus/TCP header is 7 bytes)
                response = s.recv(7)
                if len(response) < 7:
                    return None
                
                # Get remaining bytes based on length field
                length = struct.unpack('>H', response[4:6])[0]
                remaining = length - 1  # Subtract unit ID
                if remaining > 0:
                    response += s.recv(remaining)
                
                return response
        except Exception as e:
            self.logger.error(f"Error sending packet: {str(e)}")
            return None

    def is_expected_response(self, request, response):
        """Determine if response is unexpected"""
        if not response:
            return False
        
        try:
            # Parse request
            req_func_code = request[7]
            
            # Parse response
            resp_func_code = response[7]
            
            # Exception response
            if resp_func_code == (req_func_code | 0x80):
                return True  # Modbus exception is an expected response
            
            # Check function code matches
            if resp_func_code != req_func_code:
                return False
                
            # Basic length checks
            if req_func_code in [1, 2, 3, 4]:
                # Check byte count field matches quantity
                req_quantity = struct.unpack('>H', request[10:12])[0]
                byte_count = response[8]
                expected_bytes = req_quantity // 8 + (1 if req_quantity % 8 else 0) if req_func_code in [1, 2] else req_quantity * 2
                if byte_count != expected_bytes:
                    return False
                    
            return True
            
        except Exception as e:
            self.logger.error(f"Error parsing response: {str(e)}")
            return False

    def run_test(self, duration_hours=24, report_intervals=[1, 6, 12, 24]):
        """Run the fuzzing test for specified duration"""
        self.logger.info(f"Starting Modbus fuzzing test against {self.target_ip}:{self.target_port}")
        
        end_time = self.start_time + (duration_hours * 3600)
        next_report = self.start_time + 3600  # First report after 1 hour
        
        while time.time() < end_time:
            # Generate and send fuzzed packet
            packet = self.generate_fuzzed_packet()
            self.stats['packets_sent'] += 1
            
            response = self.send_packet(packet)
            
            # Check for crashes (no response)
            if response is None:
                self.stats['crashes'] += 1
                self.stats['crash_packets'].append({
                    'timestamp': datetime.now().isoformat(),
                    'packet': packet.hex()
                })
                self.logger.warning(f"CRASH detected with packet: {packet.hex()}")
                # Wait a bit to see if server recovers
                time.sleep(5)
                continue
                
            # Check for unexpected responses
            if not self.is_expected_response(packet, response):
                self.stats['unexpected_responses'] += 1
                self.stats['unexpected_response_packets'].append({
                    'timestamp': datetime.now().isoformat(),
                    'packet': packet.hex(),
                    'response': response.hex() if response else None
                })
                self.logger.info(f"Unexpected response for packet: {packet.hex()}, response: {response.hex()}")
            
            # Generate reports at specified intervals
            if time.time() >= next_report:
                elapsed_hours = (time.time() - self.start_time) / 3600
                self.generate_report(elapsed_hours)
                next_report = time.time() + 3600  # Next report in 1 hour
                
            # Small delay to avoid overwhelming the target
            time.sleep(0.05)
            
        # Final report
        self.generate_report(duration_hours)
        self.logger.info("Modbus fuzzing test completed")

    def generate_report(self, elapsed_hours):
        """Generate a fuzzing test report with all required metrics"""
        report = {
            'timestamp': datetime.now().isoformat(),
            'elapsed_hours': elapsed_hours,
            'function_code_coverage': len(self.stats['function_codes_tested']),
            'field_mutation_coverage': len(self.stats['fields_mutated']),
            'crash_number': self.stats['crashes'],
            'crashes_per_hour': self.stats['crashes'] / elapsed_hours,
            'execution_speed': self.stats['packets_sent'] / elapsed_hours,
            'crash_packet_ratio': (self.stats['packets_sent'] / self.stats['crashes']) if self.stats['crashes'] > 0 else float('inf'),
            'unexpected_responses': self.stats['unexpected_responses'],
            'unexpected_responses_per_hour': self.stats['unexpected_responses'] / elapsed_hours,
            'unexpected_response_packet_ratio': (self.stats['packets_sent'] / self.stats['unexpected_responses']) if self.stats['unexpected_responses'] > 0 else float('inf'),
            'details': {
                'function_codes_tested': sorted(list(self.stats['function_codes_tested'])),
                'fields_mutated': dict(self.stats['fields_mutated']),
                'crash_examples': self.stats['crash_packets'][-5:] if self.stats['crash_packets'] else [],
                'unexpected_response_examples': self.stats['unexpected_response_packets'][-5:] if self.stats['unexpected_response_packets'] else []
            }
        }
        
        # Save report to file
        report_filename = f"modbus_fuzz_report_{elapsed_hours}h.json"
        with open(report_filename, 'w') as f:
            json.dump(report, f, indent=2)
            
        self.logger.info(f"Generated report after {elapsed_hours} hours")
        
        return report

if __name__ == "__main__":
    # Example usage
    fuzzer = ModbusFuzzer(target_ip="192.168.1.100")
    fuzzer.run_test(duration_hours=24)
