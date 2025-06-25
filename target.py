#!/usr/bin/env python3
import socket
import struct
import time
import threading
import json
import random
from datetime import datetime, timedelta
from collections import defaultdict, Counter
import logging


logging.basicConfig(level=logging.INFO, format='%(asctime)s - %(levelname)s - %(message)s')
logger = logging.getLogger(__name__)

class ModbusSlaveStats:
    def __init__(self):
        self.start_time = datetime.now()
        self.total_packets = 0
        self.function_codes_tested = set()
        self.addresses_accessed = set()
        self.fields_mutated = set()
        self.crashes = 0
        self.anomalies = 0
        self.packet_history = []
        self.crash_history = []
        self.anomaly_history = []
        self.function_code_stats = Counter()
        self.address_range_stats = Counter()
        self.malformed_packets = 0
        self.lock = threading.Lock()
        
    def record_packet(self, function_code=None, address=None, malformed=False):
        with self.lock:
            self.total_packets += 1
            self.packet_history.append(datetime.now())
            
            if function_code is not None:
                self.function_codes_tested.add(function_code)
                self.function_code_stats[function_code] += 1
                
            if address is not None:
                self.addresses_accessed.add(address)
                self.address_range_stats[address] += 1
                
            if malformed:
                self.malformed_packets += 1
                
    def record_crash(self, reason="Unknown"):
        with self.lock:
            self.crashes += 1
            self.crash_history.append((datetime.now(), reason))
            
    def record_anomaly(self, anomaly_type="Unknown"):
        with self.lock:
            self.anomalies += 1
            self.anomaly_history.append((datetime.now(), anomaly_type))
            
    def record_field_mutation(self, field_name):
        with self.lock:
            self.fields_mutated.add(field_name)
            
    def get_runtime_hours(self):
        return (datetime.now() - self.start_time).total_seconds() / 3600
        
    def get_packets_per_second(self):
        runtime_seconds = (datetime.now() - self.start_time).total_seconds()
        return self.total_packets / runtime_seconds if runtime_seconds > 0 else 0
        
    def get_crashes_per_hour(self):
        runtime_hours = self.get_runtime_hours()
        return self.crashes / runtime_hours if runtime_hours > 0 else 0
        
    def get_anomalies_per_hour(self):
        runtime_hours = self.get_runtime_hours()
        return self.anomalies / runtime_hours if runtime_hours > 0 else 0
        
    def get_crash_packet_ratio(self):
        return self.crashes / self.total_packets if self.total_packets > 0 else 0
        
    def get_anomaly_packet_ratio(self):
        return self.anomalies / self.total_packets if self.total_packets > 0 else 0
        
    def get_report(self):
        runtime_hours = self.get_runtime_hours()
        
        return {
            "test_duration_hours": round(runtime_hours, 2),
            "metrics": {
                "function_code_coverage": {
                    "codes_tested": sorted(list(self.function_codes_tested)),
                    "total_unique_codes": len(self.function_codes_tested),
                    "distribution": dict(self.function_code_stats)
                },
                "address_range_coverage": {
                    "addresses_accessed": len(self.addresses_accessed),
                    "address_range": f"{min(self.addresses_accessed) if self.addresses_accessed else 0}-{max(self.addresses_accessed) if self.addresses_accessed else 0}",
                    "top_addresses": self.address_range_stats.most_common(10)
                },
                "field_mutation_coverage": {
                    "fields_mutated": sorted(list(self.fields_mutated)),
                    "total_fields": len(self.fields_mutated)
                },
                "execution_speed": {
                    "packets_per_second": round(self.get_packets_per_second(), 2),
                    "total_packets": self.total_packets
                },
                "crash_metrics": {
                    "total_crashes": self.crashes,
                    "crashes_per_hour": round(self.get_crashes_per_hour(), 2),
                    "crash_packet_ratio": round(self.get_crash_packet_ratio(), 6)
                },
                "anomaly_metrics": {
                    "total_anomalies": self.anomalies,
                    "anomalies_per_hour": round(self.get_anomalies_per_hour(), 2),
                    "anomaly_packet_ratio": round(self.get_anomaly_packet_ratio(), 6)
                },
                "packet_quality": {
                    "malformed_packets": self.malformed_packets,
                    "malformed_ratio": round(self.malformed_packets / self.total_packets if self.total_packets > 0 else 0, 4)
                }
            },
            "timestamp": datetime.now().isoformat()
        }

class ModbusSlave:
    def __init__(self, host='0.0.0.0', port=502):
        self.host = host
        self.port = port
        self.socket = None
        self.running = False
        self.stats = ModbusSlaveStats()
        
       
        self.coils = [False] * 10000  # 00001-09999
        self.discrete_inputs = [False] * 10000  # 10001-19999
        self.holding_registers = [0] * 10000  # 40001-49999
        self.input_registers = [0] * 10000  # 30001-39999
        
        
        for i in range(100):
            self.holding_registers[i] = random.randint(0, 65535)
            self.input_registers[i] = random.randint(0, 65535)
            
       
        self.report_thread = None
        
    def start(self):
        self.socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        self.socket.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        self.socket.bind((self.host, self.port))
        self.socket.listen(5)
        self.running = True
        
        logger.info(f"Modbus Slave avviato su {self.host}:{self.port}")
        
        
        self.report_thread = threading.Thread(target=self._periodic_report, daemon=True)
        self.report_thread.start()
        
        try:
            while self.running:
                try:
                    client_socket, addr = self.socket.accept()
                    logger.info(f"Connessione da {addr}")
                    
                    
                    client_thread = threading.Thread(
                        target=self._handle_client, 
                        args=(client_socket, addr),
                        daemon=True
                    )
                    client_thread.start()
                    
                except socket.error as e:
                    if self.running:
                        logger.error(f"Errore socket: {e}")
                        
        except KeyboardInterrupt:
            logger.info("Interrupt received, shutting down...")
        finally:
            self.stop()
            
    def stop(self):
     
        self.running = False
        if self.socket:
            self.socket.close()
        self._save_final_report()
        
    def _periodic_report(self):

        while self.running:
            time.sleep(60)
            if self.running:
                report = self.stats.get_report()
                filename = f"modbus_slave_report_{datetime.now().strftime('%Y%m%d_%H%M%S')}.json"
                with open(filename, 'w') as f:
                    json.dump(report, f, indent=2)
                logger.info(f"Report salvato: {filename}")
                
    def _save_final_report(self):
    
        report = self.stats.get_report()
        filename = f"modbus_slave_final_report_{datetime.now().strftime('%Y%m%d_%H%M%S')}.json"
        with open(filename, 'w') as f:
            json.dump(report, f, indent=2)
        logger.info(f"Report finale salvato: {filename}")
        
    def _handle_client(self, client_socket, addr):
       
        try:
            while self.running:
                data = client_socket.recv(1024)
                if not data:
                    break
                    
                response = self._process_modbus_request(data)
                if response:
                    client_socket.send(response)
                    
        except socket.error as e:
            logger.warning(f"Error with connection: {addr}: {e}")
        finally:
            client_socket.close()
            
    def _process_modbus_request(self, data):
        try:
            if len(data) < 8: 
                self.stats.record_packet(malformed=True)
                self.stats.record_anomaly("Packet too short")
                return self._create_error_response(0, 0, 0x01)  
                
          
            transaction_id, protocol_id, length, unit_id = struct.unpack('>HHHB', data[:7])
            
            if protocol_id != 0:  
                self.stats.record_packet(malformed=True)
                self.stats.record_anomaly("Invalid protocol ID")
                return self._create_error_response(transaction_id, unit_id, 0x01)
                
            if len(data) < 7 + length - 1:
                self.stats.record_packet(malformed=True)
                self.stats.record_anomaly("Length mismatch")
                return self._create_error_response(transaction_id, unit_id, 0x01)
                
           
            pdu = data[7:]
            if len(pdu) < 1:
                self.stats.record_packet(malformed=True)
                return self._create_error_response(transaction_id, unit_id, 0x01)
                
            function_code = pdu[0]
            self.stats.record_packet(function_code=function_code)
            
          
                
            return self._handle_function_code(transaction_id, unit_id, function_code, pdu[1:])
            
        except Exception as e:
            logger.error(f"Error in processing request: {e}")
            self.stats.record_crash(f"Exception: {str(e)}")
           
            return self._create_error_response(0, 0, 0x04)  
            
    def _handle_function_code(self, transaction_id, unit_id, function_code, data):
        
        try:
            if function_code == 0x01:  # Read Coils
                return self._read_coils(transaction_id, unit_id, data)
            elif function_code == 0x02:  # Read Discrete Inputs
                return self._read_discrete_inputs(transaction_id, unit_id, data)
            elif function_code == 0x03:  # Read Holding Registers
                return self._read_holding_registers(transaction_id, unit_id, data)
            elif function_code == 0x04:  # Read Input Registers
                return self._read_input_registers(transaction_id, unit_id, data)
            elif function_code == 0x05:  # Write Single Coil
                return self._write_single_coil(transaction_id, unit_id, data)
            elif function_code == 0x06:  # Write Single Register
                return self._write_single_register(transaction_id, unit_id, data)
            elif function_code == 0x0F:  # Write Multiple Coils
                return self._write_multiple_coils(transaction_id, unit_id, data)
            elif function_code == 0x10:  # Write Multiple Registers
                return self._write_multiple_registers(transaction_id, unit_id, data)
            else:
               
                return self._create_error_response(transaction_id, unit_id, 0x01)
                
        except Exception as e:
            logger.error(f"Error FC {function_code}: {e}")
            self.stats.record_crash(f"FC {function_code} Exception: {str(e)}")
            return self._create_error_response(transaction_id, unit_id, 0x04)  
            
    def _read_coils(self, transaction_id, unit_id, data):
        if len(data) < 4:
            return self._create_error_response(transaction_id, unit_id, 0x03)
            
        start_addr, quantity = struct.unpack('>HH', data[:4])
        self.stats.record_packet(address=start_addr)
        self.stats.record_field_mutation("start_address")
        self.stats.record_field_mutation("quantity")
        
        if quantity > 2000 or start_addr + quantity > len(self.coils):
            return self._create_error_response(transaction_id, unit_id, 0x02)
            
    
        coil_bytes = []
        for i in range(0, quantity, 8):
            byte_val = 0
            for j in range(8):
                if i + j < quantity and start_addr + i + j < len(self.coils):
                    if self.coils[start_addr + i + j]:
                        byte_val |= (1 << j)
            coil_bytes.append(byte_val)
            
        response_data = struct.pack('B', len(coil_bytes)) + bytes(coil_bytes)
        return self._create_response(transaction_id, unit_id, 0x01, response_data)
        
    def _read_holding_registers(self, transaction_id, unit_id, data):
        if len(data) < 4:
            return self._create_error_response(transaction_id, unit_id, 0x03)
            
        start_addr, quantity = struct.unpack('>HH', data[:4])
        self.stats.record_packet(address=start_addr)
        self.stats.record_field_mutation("start_address")
        self.stats.record_field_mutation("quantity")
        
        if quantity > 125 or start_addr + quantity > len(self.holding_registers):
            return self._create_error_response(transaction_id, unit_id, 0x02)
            
        registers = self.holding_registers[start_addr:start_addr + quantity]
        response_data = struct.pack('B', quantity * 2) + struct.pack('>' + 'H' * quantity, *registers)
        return self._create_response(transaction_id, unit_id, 0x03, response_data)
        
    def _write_single_register(self, transaction_id, unit_id, data):
        if len(data) < 4:
            return self._create_error_response(transaction_id, unit_id, 0x03)
            
        address, value = struct.unpack('>HH', data[:4])
        self.stats.record_packet(address=address)
        self.stats.record_field_mutation("register_address")
        self.stats.record_field_mutation("register_value")
        
        if address >= len(self.holding_registers):
            return self._create_error_response(transaction_id, unit_id, 0x02)
            
        self.holding_registers[address] = value
        return self._create_response(transaction_id, unit_id, 0x06, data[:4])
        
    
    def _read_discrete_inputs(self, transaction_id, unit_id, data):
        
        return self._read_coils(transaction_id, unit_id, data) 
        
    def _read_input_registers(self, transaction_id, unit_id, data):
       
        if len(data) < 4:
            return self._create_error_response(transaction_id, unit_id, 0x03)
            
        start_addr, quantity = struct.unpack('>HH', data[:4])
        self.stats.record_packet(address=start_addr)
        
        if quantity > 125 or start_addr + quantity > len(self.input_registers):
            return self._create_error_response(transaction_id, unit_id, 0x02)
            
        registers = self.input_registers[start_addr:start_addr + quantity]
        response_data = struct.pack('B', quantity * 2) + struct.pack('>' + 'H' * quantity, *registers)
        return self._create_response(transaction_id, unit_id, 0x04, response_data)
        
    def _write_single_coil(self, transaction_id, unit_id, data):
        if len(data) < 4:
            return self._create_error_response(transaction_id, unit_id, 0x03)
            
        address, value = struct.unpack('>HH', data[:4])
        self.stats.record_packet(address=address)
        
        if address >= len(self.coils):
            return self._create_error_response(transaction_id, unit_id, 0x02)
            
        self.coils[address] = value == 0xFF00
        return self._create_response(transaction_id, unit_id, 0x05, data[:4])
        
    def _write_multiple_coils(self, transaction_id, unit_id, data):
    
        return self._create_error_response(transaction_id, unit_id, 0x01)
        
    def _write_multiple_registers(self, transaction_id, unit_id, data):

        return self._create_error_response(transaction_id, unit_id, 0x01)
        
    def _create_response(self, transaction_id, unit_id, function_code, data):
       
        pdu = struct.pack('B', function_code) + data
        mbap = struct.pack('>HHHB', transaction_id, 0, len(pdu) + 1, unit_id)
        return mbap + pdu
        
    def _create_error_response(self, transaction_id, unit_id, exception_code):
       

        error_fc = 0x80 | (transaction_id & 0x7F) 
        pdu = struct.pack('BB', error_fc, exception_code)
        mbap = struct.pack('>HHHB', transaction_id, 0, len(pdu) + 1, unit_id)
        return mbap + pdu
        
    def _create_anomalous_response(self, transaction_id, unit_id, function_code):
     
        anomaly_type = random.choice([
            "wrong_length", "invalid_data", "corrupted_header", 
            "random_bytes", "truncated", "oversized"
        ])
        
        if anomaly_type == "wrong_length":
            pdu = struct.pack('B', function_code) + b'\x00\x01'
            mbap = struct.pack('>HHHB', transaction_id, 0, 999, unit_id) 
            return mbap + pdu
            
        elif anomaly_type == "random_bytes":
            return bytes([random.randint(0, 255) for _ in range(random.randint(8, 50))])
            
        elif anomaly_type == "truncated":
            return struct.pack('>HH', transaction_id, 0)
            
        elif anomaly_type == "oversized":
            pdu = struct.pack('B', function_code) + b'\x00' * 1000
            mbap = struct.pack('>HHHB', transaction_id, 0, len(pdu) + 1, unit_id)
            return mbap + pdu
            
        else:
            pdu = struct.pack('B', function_code) + b'\xFF\xFF\xFF\xFF'
            mbap = struct.pack('>HHHB', transaction_id, 0, len(pdu) + 1, unit_id)
            return mbap + pdu

def main():
    """Funzione principale"""
    import argparse
    
    parser = argparse.ArgumentParser(description='Fuzzing target')
    parser.add_argument('--host', default='0.0.0.0', help=' IP (default: 0.0.0.0)')
    parser.add_argument('--port', type=int, default=502, help=' Port (default: 502)')
    
    args = parser.parse_args()
    
    slave = ModbusSlave(args.host, args.port)
    
    try:
        slave.start()
    except KeyboardInterrupt:
        logger.info("Shutting down...")
        slave.stop()

if __name__ == "__main__":
    main()
