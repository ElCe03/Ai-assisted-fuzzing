#!/usr/bin/env python3
"""
Advanced Modbus Protocol Fuzzer
Performs exhaustive fuzzing tests against Modbus TCP/RTU slaves
Author: Claude AI Assistant
"""

import socket
import struct
import time
import random
import threading
import json
import logging
from datetime import datetime, timedelta
from dataclasses import dataclass, asdict
from typing import List, Dict, Any, Optional, Tuple
from enum import Enum
import sys
import os

# Configure logging
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(levelname)s - %(message)s',
    handlers=[
        logging.FileHandler('modbus_fuzzer.log'),
        logging.StreamHandler(sys.stdout)
    ]
)
logger = logging.getLogger(__name__)

class ModbusFunction(Enum):
    """Modbus function codes"""
    READ_COILS = 0x01
    READ_DISCRETE_INPUTS = 0x02
    READ_HOLDING_REGISTERS = 0x03
    READ_INPUT_REGISTERS = 0x04
    WRITE_SINGLE_COIL = 0x05
    WRITE_SINGLE_REGISTER = 0x06
    READ_EXCEPTION_STATUS = 0x07
    DIAGNOSTICS = 0x08
    GET_COMM_EVENT_COUNTER = 0x0B
    GET_COMM_EVENT_LOG = 0x0C
    WRITE_MULTIPLE_COILS = 0x0F
    WRITE_MULTIPLE_REGISTERS = 0x10
    REPORT_SLAVE_ID = 0x11
    READ_FILE_RECORD = 0x14
    WRITE_FILE_RECORD = 0x15
    MASK_WRITE_REGISTER = 0x16
    READ_WRITE_MULTIPLE_REGISTERS = 0x17
    READ_FIFO_QUEUE = 0x18
    ENCAPSULATED_INTERFACE_TRANSPORT = 0x2B

@dataclass
class FuzzingStats:
    """Statistics tracking for fuzzing session"""
    start_time: datetime
    packets_sent: int = 0
    crashes: int = 0
    unexpected_responses: int = 0
    function_codes_tested: set = None
    fields_mutated: set = None
    crash_packets: List[Dict] = None
    unexpected_packets: List[Dict] = None
    
    def __post_init__(self):
        if self.function_codes_tested is None:
            self.function_codes_tested = set()
        if self.fields_mutated is None:
            self.fields_mutated = set()
        if self.crash_packets is None:
            self.crash_packets = []
        if self.unexpected_packets is None:
            self.unexpected_packets = []

class ModbusPacket:
    """Modbus TCP packet structure"""
    
    def __init__(self, transaction_id=1, protocol_id=0, unit_id=1, 
                 function_code=3, data=b''):
        self.transaction_id = transaction_id
        self.protocol_id = protocol_id
        self.length = len(data) + 2  # function code + unit id + data
        self.unit_id = unit_id
        self.function_code = function_code
        self.data = data
    
    def to_bytes(self) -> bytes:
        """Convert packet to bytes"""
        header = struct.pack('>HHHB', 
                           self.transaction_id, 
                           self.protocol_id,
                           self.length,
                           self.unit_id)
        return header + struct.pack('B', self.function_code) + self.data
    
    @classmethod
    def from_bytes(cls, data: bytes):
        """Parse packet from bytes"""
        if len(data) < 8:
            raise ValueError("Packet too short")
        
        header = struct.unpack('>HHHB', data[:7])
        transaction_id, protocol_id, length, unit_id = header
        
        if len(data) < 7 + length:
            raise ValueError("Incomplete packet")
        
        function_code = data[7]
        payload = data[8:7+length]
        
        return cls(transaction_id, protocol_id, unit_id, function_code, payload)

class ModbusFuzzer:
    """Advanced Modbus Protocol Fuzzer"""
    
    def __init__(self, target_host: str, target_port: int = 502, 
                 timeout: float = 1.0, max_retries: int = 3):
        self.target_host = target_host
        self.target_port = target_port
        self.timeout = timeout
        self.max_retries = max_retries
        self.stats = FuzzingStats(start_time=datetime.now())
        self.running = False
        self.connection_lost = False
        
        # Fuzzing strategies
        self.strategies = [
            self._fuzz_function_codes,
            self._fuzz_data_lengths,
            self._fuzz_register_addresses,
            self._fuzz_register_counts,
            self._fuzz_data_values,
            self._fuzz_header_fields,
            self._fuzz_malformed_packets,
            self._fuzz_boundary_values,
            self._fuzz_protocol_violations
        ]
        
        # Valid Modbus function codes for testing
        self.valid_functions = [fc.value for fc in ModbusFunction]
        
        # Field mutation tracking
        self.mutation_fields = [
            'transaction_id', 'protocol_id', 'length', 'unit_id',
            'function_code', 'address', 'count', 'data_length', 'data_values'
        ]
    
    def connect(self) -> socket.socket:
        """Establish connection to Modbus slave"""
        try:
            sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            sock.settimeout(self.timeout)
            sock.connect((self.target_host, self.target_port))
            return sock
        except Exception as e:
            logger.error(f"Connection failed: {e}")
            self.connection_lost = True
            return None
    
    def send_packet(self, packet: ModbusPacket) -> Tuple[bool, bytes, str]:
        """Send packet and analyze response"""
        sock = None
        try:
            sock = self.connect()
            if not sock:
                return False, b'', 'connection_failed'
            
            packet_bytes = packet.to_bytes()
            sock.send(packet_bytes)
            
            try:
                response = sock.recv(1024)
                self.stats.packets_sent += 1
                
                # Analyze response
                if len(response) == 0:
                    return False, response, 'empty_response'
                
                # Check for Modbus exception
                if len(response) >= 8 and response[7] & 0x80:
                    exception_code = response[8] if len(response) > 8 else 0
                    if exception_code not in [1, 2, 3, 4, 5, 6, 10, 11]:
                        return False, response, 'invalid_exception'
                
                # Check response validity
                if not self._is_valid_response(packet, response):
                    return False, response, 'unexpected_response'
                
                return True, response, 'valid'
                
            except socket.timeout:
                return False, b'', 'timeout'
            
        except Exception as e:
            logger.debug(f"Send packet error: {e}")
            return False, b'', 'error'
        finally:
            if sock:
                sock.close()
    
    def _is_valid_response(self, request: ModbusPacket, response: bytes) -> bool:
        """Validate Modbus response"""
        try:
            if len(response) < 8:
                return False
            
            # Parse response header
            resp_trans_id, resp_proto_id, resp_length, resp_unit_id = struct.unpack('>HHHB', response[:7])
            resp_func_code = response[7]
            
            # Check transaction ID match
            if resp_trans_id != request.transaction_id:
                return False
            
            # Check protocol ID
            if resp_proto_id != 0:
                return False
            
            # Check unit ID match
            if resp_unit_id != request.unit_id:
                return False
            
            # Check function code (exception or normal)
            if resp_func_code & 0x80:  # Exception response
                return resp_func_code == (request.function_code | 0x80)
            else:  # Normal response
                return resp_func_code == request.function_code
            
        except:
            return False
    
    def _log_anomaly(self, packet: ModbusPacket, response: bytes, 
                    anomaly_type: str, description: str):
        """Log crash or unexpected response"""
        packet_info = {
            'timestamp': datetime.now().isoformat(),
            'packet': {
                'transaction_id': packet.transaction_id,
                'protocol_id': packet.protocol_id,
                'length': packet.length,
                'unit_id': packet.unit_id,
                'function_code': packet.function_code,
                'data': packet.data.hex()
            },
            'response': response.hex() if response else '',
            'anomaly_type': anomaly_type,
            'description': description
        }
        
        if anomaly_type == 'crash':
            self.stats.crashes += 1
            self.stats.crash_packets.append(packet_info)
            logger.warning(f"CRASH DETECTED: {description}")
        else:
            self.stats.unexpected_responses += 1
            self.stats.unexpected_packets.append(packet_info)
            logger.info(f"Unexpected response: {description}")
        
        # Save to file immediately
        filename = f"anomalies_{datetime.now().strftime('%Y%m%d_%H%M%S')}.json"
        try:
            with open(filename, 'a') as f:
                json.dump(packet_info, f)
                f.write('\n')
        except Exception as e:
            logger.error(f"Failed to save anomaly: {e}")
    
    def _fuzz_function_codes(self):
        """Fuzz with various function codes"""
        self.stats.fields_mutated.add('function_code')
        
        # Test valid function codes
        for func_code in self.valid_functions:
            self.stats.function_codes_tested.add(func_code)
            
            if func_code in [1, 2, 3, 4]:  # Read functions
                data = struct.pack('>HH', 0, 10)  # address=0, count=10
            elif func_code == 5:  # Write single coil
                data = struct.pack('>HH', 0, 0xFF00)  # address=0, value=ON
            elif func_code == 6:  # Write single register
                data = struct.pack('>HH', 0, 0x1234)  # address=0, value=0x1234
            else:
                data = b'\x00' * random.randint(0, 10)
            
            packet = ModbusPacket(function_code=func_code, data=data)
            success, response, status = self.send_packet(packet)
            
            if status == 'connection_failed':
                self._log_anomaly(packet, response, 'crash', 'Connection failed - possible crash')
            elif status == 'unexpected_response':
                self._log_anomaly(packet, response, 'unexpected', f'Unexpected response to function {func_code}')
        
        # Test invalid function codes
        for func_code in range(256):
            if func_code not in self.valid_functions:
                self.stats.function_codes_tested.add(func_code)
                packet = ModbusPacket(function_code=func_code, data=b'\x00\x00\x00\x10')
                success, response, status = self.send_packet(packet)
                
                if status == 'connection_failed':
                    self._log_anomaly(packet, response, 'crash', f'Crash on invalid function code {func_code}')
    
    def _fuzz_data_lengths(self):
        """Fuzz with various data lengths"""
        self.stats.fields_mutated.add('data_length')
        
        # Test boundary lengths
        lengths = [0, 1, 2, 125, 126, 127, 128, 250, 251, 252, 253, 254, 255, 256, 512, 1024, 2048, 4096]
        
        for length in lengths:
            data = b'\x00' * length
            packet = ModbusPacket(function_code=3, data=data)
            packet.length = length + 2  # Override length field
            
            success, response, status = self.send_packet(packet)
            
            if status == 'connection_failed':
                self._log_anomaly(packet, response, 'crash', f'Crash on data length {length}')
            elif status == 'unexpected_response':
                self._log_anomaly(packet, response, 'unexpected', f'Unexpected response to length {length}')
    
    def _fuzz_register_addresses(self):
        """Fuzz register addresses"""
        self.stats.fields_mutated.add('address')
        
        # Boundary addresses
        addresses = [0, 1, 0xFFFF, 0x10000, 0xFFFFFFFF]
        
        for addr in addresses:
            if addr > 0xFFFF:
                # Use 32-bit address (invalid for standard Modbus)
                data = struct.pack('>LH', addr, 1)
            else:
                data = struct.pack('>HH', addr, 1)
            
            packet = ModbusPacket(function_code=3, data=data)
            success, response, status = self.send_packet(packet)
            
            if status == 'connection_failed':
                self._log_anomaly(packet, response, 'crash', f'Crash on address {addr}')
    
    def _fuzz_register_counts(self):
        """Fuzz register counts"""
        self.stats.fields_mutated.add('count')
        
        # Boundary counts
        counts = [0, 1, 125, 126, 127, 128, 0xFFFF, 0x10000]
        
        for count in counts:
            if count > 0xFFFF:
                data = struct.pack('>HL', 0, count)
            else:
                data = struct.pack('>HH', 0, count)
            
            packet = ModbusPacket(function_code=3, data=data)
            success, response, status = self.send_packet(packet)
            
            if status == 'connection_failed':
                self._log_anomaly(packet, response, 'crash', f'Crash on count {count}')
    
    def _fuzz_data_values(self):
        """Fuzz data values"""
        self.stats.fields_mutated.add('data_values')
        
        # Test various data patterns
        patterns = [
            b'\x00' * 100,  # All zeros
            b'\xFF' * 100,  # All ones
            b'\xAA' * 100,  # Alternating pattern
            b'\x55' * 100,  # Alternating pattern
        ]
        
        for pattern in patterns:
            packet = ModbusPacket(function_code=16, data=struct.pack('>HHB', 0, len(pattern)//2, len(pattern)) + pattern)
            success, response, status = self.send_packet(packet)
            
            if status == 'connection_failed':
                self._log_anomaly(packet, response, 'crash', f'Crash on data pattern')
    
    def _fuzz_header_fields(self):
        """Fuzz header fields"""
        for field in ['transaction_id', 'protocol_id', 'unit_id']:
            self.stats.fields_mutated.add(field)
        
        # Test boundary values for header fields
        values = [0, 1, 0x7FFF, 0x8000, 0xFFFF, 0x10000]
        
        for val in values:
            packet = ModbusPacket(
                transaction_id=val & 0xFFFF,
                protocol_id=val & 0xFFFF if val < 0x10000 else 0xFFFF,
                unit_id=val & 0xFF,
                function_code=3,
                data=struct.pack('>HH', 0, 1)
            )
            
            success, response, status = self.send_packet(packet)
            
            if status == 'connection_failed':
                self._log_anomaly(packet, response, 'crash', f'Crash on header field value {val}')
    
    def _fuzz_malformed_packets(self):
        """Send malformed packets"""
        self.stats.fields_mutated.add('packet_structure')
        
        # Truncated packets
        for i in range(1, 10):
            truncated = struct.pack('>H', 1)[:i]  # Truncated header
            try:
                sock = self.connect()
                if sock:
                    sock.send(truncated)
                    try:
                        response = sock.recv(1024)
                        if not response:
                            logger.warning("No response to truncated packet - possible crash")
                    except:
                        pass
                    sock.close()
            except:
                logger.warning(f"Exception on truncated packet length {i}")
    
    def _fuzz_boundary_values(self):
        """Test boundary values"""
        self.stats.fields_mutated.add('boundary_values')
        
        # Integer overflow/underflow tests
        boundary_values = [
            0x7F, 0x80, 0xFF, 0x100,
            0x7FFF, 0x8000, 0xFFFF, 0x10000,
            0x7FFFFFFF, 0x80000000, 0xFFFFFFFF
        ]
        
        for val in boundary_values:
            # Test as different field types
            data_variants = [
                struct.pack('>H', val & 0xFFFF),
                struct.pack('>I', val & 0xFFFFFFFF),
                struct.pack('>Q', val & 0xFFFFFFFFFFFFFFFF),
            ]
            
            for data in data_variants:
                packet = ModbusPacket(function_code=3, data=data)
                success, response, status = self.send_packet(packet)
                
                if status == 'connection_failed':
                    self._log_anomaly(packet, response, 'crash', f'Crash on boundary value {val}')
    
    def _fuzz_protocol_violations(self):
        """Test protocol violations"""
        self.stats.fields_mutated.add('protocol_violations')
        
        # Invalid length field
        packet = ModbusPacket(function_code=3, data=struct.pack('>HH', 0, 1))
        packet.length = 0  # Invalid length
        success, response, status = self.send_packet(packet)
        
        if status == 'connection_failed':
            self._log_anomaly(packet, response, 'crash', 'Crash on invalid length field')
        
        # Mismatched length
        packet = ModbusPacket(function_code=3, data=struct.pack('>HH', 0, 1))
        packet.length = 100  # Much larger than actual data
        success, response, status = self.send_packet(packet)
        
        if status == 'connection_failed':
            self._log_anomaly(packet, response, 'crash', 'Crash on mismatched length')
    
    def generate_report(self, elapsed_hours: float) -> Dict[str, Any]:
        """Generate fuzzing report"""
        elapsed_seconds = elapsed_hours * 3600
        
        report = {
            'timestamp': datetime.now().isoformat(),
            'elapsed_hours': elapsed_hours,
            'function_code_coverage': len(self.stats.function_codes_tested),
            'field_mutation_coverage': len(self.stats.fields_mutated),
            'crash_number': self.stats.crashes,
            'crash_per_hour': self.stats.crashes / elapsed_hours if elapsed_hours > 0 else 0,
            'execution_speed': self.stats.packets_sent / elapsed_seconds if elapsed_seconds > 0 else 0,
            'crash_packet_ratio': self.stats.packets_sent / self.stats.crashes if self.stats.crashes > 0 else float('inf'),
            'unexpected_responses': self.stats.unexpected_responses,
            'unexpected_response_per_hour': self.stats.unexpected_responses / elapsed_hours if elapsed_hours > 0 else 0,
            'unexpected_response_packet_ratio': self.stats.packets_sent / self.stats.unexpected_responses if self.stats.unexpected_responses > 0 else float('inf'),
            'total_packets_sent': self.stats.packets_sent,
            'function_codes_tested': sorted(list(self.stats.function_codes_tested)),
            'fields_mutated': sorted(list(self.stats.fields_mutated))
        }
        
        return report
    
    def save_report(self, report: Dict[str, Any], filename: str):
        """Save report to file"""
        try:
            with open(filename, 'w') as f:
                json.dump(report, f, indent=2, default=str)
            
            # Also create a human-readable summary
            summary_file = filename.replace('.json', '_summary.txt')
            with open(summary_file, 'w') as f:
                f.write(f"Modbus Fuzzing Report - {report['timestamp']}\n")
                f.write("=" * 50 + "\n\n")
                f.write(f"Test Duration: {report['elapsed_hours']:.2f} hours\n")
                f.write(f"Function Code Coverage: {report['function_code_coverage']}\n")
                f.write(f"Field Mutation Coverage: {report['field_mutation_coverage']}\n")
                f.write(f"Total Packets Sent: {report['total_packets_sent']}\n")
                f.write(f"Execution Speed: {report['execution_speed']:.2f} packets/second\n\n")
                
                f.write("CRASH STATISTICS:\n")
                f.write(f"  Total Crashes: {report['crash_number']}\n")
                f.write(f"  Crashes/Hour: {report['crash_per_hour']:.2f}\n")
                f.write(f"  Crash/Packet Ratio: 1 crash per {report['crash_packet_ratio']:.0f} packets\n\n")
                
                f.write("UNEXPECTED RESPONSE STATISTICS:\n")
                f.write(f"  Total Unexpected Responses: {report['unexpected_responses']}\n")
                f.write(f"  Unexpected Responses/Hour: {report['unexpected_response_per_hour']:.2f}\n")
                f.write(f"  Unexpected Response/Packet Ratio: 1 per {report['unexpected_response_packet_ratio']:.0f} packets\n\n")
                
                f.write(f"Function Codes Tested: {report['function_codes_tested']}\n")
                f.write(f"Fields Mutated: {report['fields_mutated']}\n")
            
            logger.info(f"Report saved to {filename} and {summary_file}")
            
        except Exception as e:
            logger.error(f"Failed to save report: {e}")
    
    def run_fuzzing_session(self, duration_hours: float = 24.0):
        """Run complete fuzzing session"""
        logger.info(f"Starting Modbus fuzzing session against {self.target_host}:{self.target_port}")
        logger.info(f"Duration: {duration_hours} hours")
        
        self.running = True
        start_time = datetime.now()
        end_time = start_time + timedelta(hours=duration_hours)
        
        # Report intervals
        report_times = [1, 6, 12, duration_hours]
        next_report_idx = 0
        
        iteration = 0
        
        try:
            while datetime.now() < end_time and self.running:
                # Run all fuzzing strategies
                for strategy in self.strategies:
                    if not self.running or datetime.now() >= end_time:
                        break
                    
                    try:
                        strategy()
                    except Exception as e:
                        logger.error(f"Strategy error: {e}")
                    
                    # Check if it's time for a report
                    elapsed = (datetime.now() - start_time).total_seconds() / 3600
                    
                    if (next_report_idx < len(report_times) and 
                        elapsed >= report_times[next_report_idx]):
                        
                        report = self.generate_report(elapsed)
                        filename = f"modbus_fuzzing_report_{report_times[next_report_idx]}h.json"
                        self.save_report(report, filename)
                        
                        logger.info(f"Report generated at {elapsed:.1f} hours:")
                        logger.info(f"  Packets sent: {self.stats.packets_sent}")
                        logger.info(f"  Crashes: {self.stats.crashes}")
                        logger.info(f"  Unexpected responses: {self.stats.unexpected_responses}")
                        logger.info(f"  Function codes tested: {len(self.stats.function_codes_tested)}")
                        
                        next_report_idx += 1
                
                iteration += 1
                
                # Brief pause to prevent excessive CPU usage
                time.sleep(0.001)
                
        except KeyboardInterrupt:
            logger.info("Fuzzing interrupted by user")
        except Exception as e:
            logger.error(f"Fuzzing session error: {e}")
        finally:
            self.running = False
            
            # Generate final report
            elapsed = (datetime.now() - start_time).total_seconds() / 3600
            final_report = self.generate_report(elapsed)
            self.save_report(final_report, "modbus_fuzzing_final_report.json")
            
            logger.info("Fuzzing session completed")
            logger.info(f"Final statistics:")
            logger.info(f"  Duration: {elapsed:.2f} hours")
            logger.info(f"  Total packets: {self.stats.packets_sent}")
            logger.info(f"  Crashes found: {self.stats.crashes}")
            logger.info(f"  Unexpected responses: {self.stats.unexpected_responses}")
            logger.info(f"  Function codes tested: {len(self.stats.function_codes_tested)}")
            logger.info(f"  Execution speed: {self.stats.packets_sent / (elapsed * 3600):.2f} packets/second")

def main():
    """Main function"""
    if len(sys.argv) < 2:
        print("Usage: python modbus_fuzzer.py <target_host> [target_port] [duration_hours]")
        print("Example: python modbus_fuzzer.py 192.168.1.100 502 24")
        sys.exit(1)
    
    target_host = sys.argv[1]
    target_port = int(sys.argv[2]) if len(sys.argv) > 2 else 502
    duration_hours = float(sys.argv[3]) if len(sys.argv) > 3 else 24.0
    
    # Test initial connection
    try:
        test_sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        test_sock.settimeout(5)
        test_sock.connect((target_host, target_port))
        test_sock.close()
        print(f"✓ Successfully connected to {target_host}:{target_port}")
    except Exception as e:
        print(f"✗ Cannot connect to {target_host}:{target_port}: {e}")
        sys.exit(1)
    
    # Create and run fuzzer
    fuzzer = ModbusFuzzer(target_host, target_port)
    
    try:
        fuzzer.run_fuzzing_session(duration_hours)
    except KeyboardInterrupt:
        print("\nFuzzing interrupted by user")
        fuzzer.running = False

if __name__ == "__main__":
    main()
