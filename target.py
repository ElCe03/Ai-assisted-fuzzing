#!/usr/bin/env python3
"""
Vulnerable Modbus TCP Slave Simulator
A deliberately vulnerable Modbus server for fuzzing and security testing
WARNING: This is for educational/testing purposes only - contains intentional vulnerabilities
Author: Claude AI Assistant
"""

import socket
import struct
import threading
import time
import random
import logging
from datetime import datetime
from typing import Dict, List, Optional, Tuple
import sys
import os

# Configure logging
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(levelname)s - %(message)s',
    handlers=[
        logging.FileHandler('modbus_slave.log'),
        logging.StreamHandler(sys.stdout)
    ]
)
logger = logging.getLogger(__name__)

class ModbusException(Exception):
    """Modbus exception codes"""
    ILLEGAL_FUNCTION = 0x01
    ILLEGAL_DATA_ADDRESS = 0x02
    ILLEGAL_DATA_VALUE = 0x03
    SLAVE_DEVICE_FAILURE = 0x04
    ACKNOWLEDGE = 0x05
    SLAVE_DEVICE_BUSY = 0x06
    MEMORY_PARITY_ERROR = 0x08
    GATEWAY_PATH_UNAVAILABLE = 0x0A
    GATEWAY_TARGET_DEVICE_FAILED = 0x0B

class VulnerableModbusSlave:
    """Vulnerable Modbus TCP Slave with intentional security flaws"""
    
    def __init__(self, host='0.0.0.0', port=502):
        self.host = host
        self.port = port
        self.running = False
        self.connections = []
        
        # Memory areas (intentionally small to trigger overflows)
        self.coils = [False] * 100  # 100 coils
        self.discrete_inputs = [False] * 100  # 100 discrete inputs
        self.holding_registers = [0] * 50  # 50 holding registers (intentionally small)
        self.input_registers = [0] * 100  # 100 input registers
        
        # Vulnerability flags
        self.crash_on_large_count = True
        self.buffer_overflow_vulnerable = True
        self.stack_overflow_vulnerable = True
        self.null_pointer_vulnerable = True
        self.integer_overflow_vulnerable = True
        
        # Statistics
        self.requests_handled = 0
        self.exceptions_sent = 0
        self.crashes_simulated = 0
        
        # Initialize some test data
        self._initialize_test_data()
    
    def _initialize_test_data(self):
        """Initialize test data in memory areas"""
        # Set some coils
        for i in range(0, 50, 5):
            if i < len(self.coils):
                self.coils[i] = True
        
        # Set some discrete inputs
        for i in range(0, 100, 3):
            if i < len(self.discrete_inputs):
                self.discrete_inputs[i] = True
        
        # Set some register values
        for i in range(len(self.holding_registers)):
            self.holding_registers[i] = 0x1000 + i
        
        for i in range(len(self.input_registers)):
            self.input_registers[i] = 0x2000 + i
    
    def _pack_modbus_response(self, transaction_id: int, unit_id: int, 
                            function_code: int, data: bytes) -> bytes:
        """Pack Modbus TCP response"""
        protocol_id = 0
        length = len(data) + 2  # function code + unit id + data
        
        header = struct.pack('>HHHB', transaction_id, protocol_id, length, unit_id)
        return header + struct.pack('B', function_code) + data
    
    def _pack_exception_response(self, transaction_id: int, unit_id: int,
                               function_code: int, exception_code: int) -> bytes:
        """Pack Modbus exception response"""
        exc_function_code = function_code | 0x80
        data = struct.pack('B', exception_code)
        return self._pack_modbus_response(transaction_id, unit_id, exc_function_code, data)
    
    def _simulate_crash(self, reason: str):
        """Simulate a crash condition"""
        self.crashes_simulated += 1
        logger.error(f"SIMULATED CRASH: {reason}")
        
        # Simulate different types of crashes
        if "buffer overflow" in reason.lower():
            # Simulate buffer overflow - close connection abruptly
            return "connection_close"
        elif "stack overflow" in reason.lower():
            # Simulate stack overflow - send malformed response
            return "malformed_response"
        elif "null pointer" in reason.lower():
            # Simulate null pointer dereference - no response
            return "no_response"
        elif "integer overflow" in reason.lower():
            # Simulate integer overflow - send invalid data
            return "invalid_response"
        else:
            return "connection_close"
    
    def _handle_read_coils(self, transaction_id: int, unit_id: int, data: bytes) -> bytes:
        """Handle Read Coils (0x01)"""
        try:
            if len(data) < 4:
                return self._pack_exception_response(transaction_id, unit_id, 0x01, 
                                                   ModbusException.ILLEGAL_DATA_VALUE)
            
            start_addr, count = struct.unpack('>HH', data[:4])
            
            # VULNERABILITY: No bounds checking
            if self.buffer_overflow_vulnerable and count > 2000:
                crash_type = self._simulate_crash("Buffer overflow in read coils")
                if crash_type == "connection_close":
                    return None
                elif crash_type == "no_response":
                    return b""
            
            # VULNERABILITY: Integer overflow
            if self.integer_overflow_vulnerable and start_addr + count > 0xFFFF:
                crash_result = self._simulate_crash("Integer overflow in address calculation")
                if crash_result == "invalid_response":
                    # Return response with corrupted data
                    corrupted_data = b'\xFF' * 50
                    return self._pack_modbus_response(transaction_id, unit_id, 0x01, corrupted_data)
            
            # Normal bounds checking (but vulnerable)
            if start_addr >= len(self.coils):
                return self._pack_exception_response(transaction_id, unit_id, 0x01,
                                                   ModbusException.ILLEGAL_DATA_ADDRESS)
            
            # Calculate response
            byte_count = (count + 7) // 8
            coil_data = bytearray(byte_count)
            
            for i in range(count):
                if start_addr + i < len(self.coils) and self.coils[start_addr + i]:
                    byte_idx = i // 8
                    bit_idx = i % 8
                    coil_data[byte_idx] |= (1 << bit_idx)
            
            response_data = struct.pack('B', byte_count) + bytes(coil_data)
            return self._pack_modbus_response(transaction_id, unit_id, 0x01, response_data)
            
        except Exception as e:
            logger.error(f"Error in read coils: {e}")
            return self._pack_exception_response(transaction_id, unit_id, 0x01,
                                               ModbusException.SLAVE_DEVICE_FAILURE)
    
    def _handle_read_holding_registers(self, transaction_id: int, unit_id: int, data: bytes) -> bytes:
        """Handle Read Holding Registers (0x03)"""
        try:
            if len(data) < 4:
                return self._pack_exception_response(transaction_id, unit_id, 0x03,
                                                   ModbusException.ILLEGAL_DATA_VALUE)
            
            start_addr, count = struct.unpack('>HH', data[:4])
            
            # VULNERABILITY: Crash on large count values
            if self.crash_on_large_count and count > 125:
                crash_type = self._simulate_crash(f"Large register count triggered crash: {count}")
                if crash_type == "connection_close":
                    return None
            
            # VULNERABILITY: No proper bounds checking
            if start_addr >= len(self.holding_registers):
                if self.null_pointer_vulnerable and start_addr > 1000:
                    crash_type = self._simulate_crash("Null pointer dereference on invalid address")
                    return b""  # No response
                
                return self._pack_exception_response(transaction_id, unit_id, 0x03,
                                                   ModbusException.ILLEGAL_DATA_ADDRESS)
            
            # Read registers (vulnerable to out-of-bounds read)
            byte_count = count * 2
            register_data = bytearray()
            
            for i in range(count):
                reg_addr = start_addr + i
                if reg_addr < len(self.holding_registers):
                    value = self.holding_registers[reg_addr]
                else:
                    # VULNERABILITY: Reading beyond array bounds
                    value = 0xDEAD  # Simulate reading garbage memory
                
                register_data.extend(struct.pack('>H', value))
            
            response_data = struct.pack('B', byte_count) + bytes(register_data)
            return self._pack_modbus_response(transaction_id, unit_id, 0x03, response_data)
            
        except Exception as e:
            logger.error(f"Error in read holding registers: {e}")
            return self._pack_exception_response(transaction_id, unit_id, 0x03,
                                               ModbusException.SLAVE_DEVICE_FAILURE)
    
    def _handle_write_single_register(self, transaction_id: int, unit_id: int, data: bytes) -> bytes:
        """Handle Write Single Register (0x06)"""
        try:
            if len(data) < 4:
                return self._pack_exception_response(transaction_id, unit_id, 0x06,
                                                   ModbusException.ILLEGAL_DATA_VALUE)
            
            addr, value = struct.unpack('>HH', data[:4])
            
            # VULNERABILITY: Magic values that cause crashes
            if value == 0xDEAD:
                crash_type = self._simulate_crash("Magic value 0xDEAD triggered crash")
                return None
            
            if value == 0xBEEF:
                crash_type = self._simulate_crash("Magic value 0xBEEF caused stack overflow")
                if crash_type == "malformed_response":
                    # Return malformed response
                    return b'\x00\x01\x00\x00\x00\x06\x01\x86\xFF'  # Malformed packet
            
            # VULNERABILITY: No bounds checking on write
            if addr < len(self.holding_registers):
                self.holding_registers[addr] = value
            else:
                # VULNERABILITY: Writing beyond array bounds (buffer overflow)
                if self.buffer_overflow_vulnerable:
                    crash_type = self._simulate_crash("Buffer overflow on register write")
                    return None
            
            # Echo back the request (normal response)
            return self._pack_modbus_response(transaction_id, unit_id, 0x06, data[:4])
            
        except Exception as e:
            logger.error(f"Error in write single register: {e}")
            return self._pack_exception_response(transaction_id, unit_id, 0x06,
                                               ModbusException.SLAVE_DEVICE_FAILURE)
    
    def _handle_write_multiple_registers(self, transaction_id: int, unit_id: int, data: bytes) -> bytes:
        """Handle Write Multiple Registers (0x10)"""
        try:
            if len(data) < 5:
                return self._pack_exception_response(transaction_id, unit_id, 0x10,
                                                   ModbusException.ILLEGAL_DATA_VALUE)
            
            start_addr, count, byte_count = struct.unpack('>HHB', data[:5])
            
            # VULNERABILITY: Stack overflow on large writes
            if self.stack_overflow_vulnerable and count > 50:
                crash_type = self._simulate_crash(f"Stack overflow on large write: {count} registers")
                if crash_type == "connection_close":
                    return None
            
            if len(data) < 5 + byte_count:
                return self._pack_exception_response(transaction_id, unit_id, 0x10,
                                                   ModbusException.ILLEGAL_DATA_VALUE)
            
            register_data = data[5:5+byte_count]
            
            # Write registers (vulnerable)
            for i in range(count):
                if i * 2 + 1 < len(register_data):
                    value = struct.unpack('>H', register_data[i*2:i*2+2])[0]
                    reg_addr = start_addr + i
                    
                    if reg_addr < len(self.holding_registers):
                        self.holding_registers[reg_addr] = value
                    # VULNERABILITY: Silent failure on out-of-bounds write
            
            # Response: echo start address and count
            response_data = struct.pack('>HH', start_addr, count)
            return self._pack_modbus_response(transaction_id, unit_id, 0x10, response_data)
            
        except Exception as e:
            logger.error(f"Error in write multiple registers: {e}")
            return self._pack_exception_response(transaction_id, unit_id, 0x10,
                                               ModbusException.SLAVE_DEVICE_FAILURE)
    
    def _handle_invalid_function(self, transaction_id: int, unit_id: int, 
                               function_code: int, data: bytes) -> bytes:
        """Handle invalid function codes"""
        
        # VULNERABILITY: Certain invalid function codes cause crashes
        crash_functions = [0x80, 0x81, 0x90, 0xFF]
        
        if function_code in crash_functions:
            crash_type = self._simulate_crash(f"Invalid function code {function_code:02X} caused crash")
            if crash_type == "connection_close":
                return None
            elif crash_type == "no_response":
                return b""
        
        # Some invalid functions return unexpected responses
        if function_code == 0x99:
            # Return response with wrong function code
            return self._pack_modbus_response(transaction_id, unit_id, 0x03, b'\x02\x12\x34')
        
        return self._pack_exception_response(transaction_id, unit_id, function_code,
                                           ModbusException.ILLEGAL_FUNCTION)
    
    def _process_request(self, request_data: bytes) -> Optional[bytes]:
        """Process Modbus request and return response"""
        try:
            if len(request_data) < 8:
                logger.warning("Request too short")
                return None
            
            # Parse header
            transaction_id, protocol_id, length, unit_id = struct.unpack('>HHHB', request_data[:7])
            
            if protocol_id != 0:
                logger.warning(f"Invalid protocol ID: {protocol_id}")
                return None
            
            if len(request_data) < 7 + length:
                logger.warning("Incomplete request")
                return None
            
            function_code = request_data[7]
            data = request_data[8:7+length]
            
            self.requests_handled += 1
            
            logger.debug(f"Processing: TID={transaction_id}, Unit={unit_id}, "
                        f"Func={function_code:02X}, DataLen={len(data)}")
            
            # Handle different function codes
            if function_code == 0x01:  # Read Coils
                return self._handle_read_coils(transaction_id, unit_id, data)
            elif function_code == 0x02:  # Read Discrete Inputs
                return self._handle_read_coils(transaction_id, unit_id, data)  # Same logic
            elif function_code == 0x03:  # Read Holding Registers
                return self._handle_read_holding_registers(transaction_id, unit_id, data)
            elif function_code == 0x04:  # Read Input Registers
                return self._handle_read_holding_registers(transaction_id, unit_id, data)  # Same logic
            elif function_code == 0x05:  # Write Single Coil
                # Simple implementation
                if len(data) >= 4:
                    addr, value = struct.unpack('>HH', data[:4])
                    if addr < len(self.coils):
                        self.coils[addr] = (value == 0xFF00)
                    return self._pack_modbus_response(transaction_id, unit_id, 0x05, data[:4])
                else:
                    return self._pack_exception_response(transaction_id, unit_id, 0x05,
                                                       ModbusException.ILLEGAL_DATA_VALUE)
            elif function_code == 0x06:  # Write Single Register
                return self._handle_write_single_register(transaction_id, unit_id, data)
            elif function_code == 0x10:  # Write Multiple Registers
                return self._handle_write_multiple_registers(transaction_id, unit_id, data)
            else:
                # Handle invalid/unsupported function codes
                return self._handle_invalid_function(transaction_id, unit_id, function_code, data)
                
        except Exception as e:
            logger.error(f"Error processing request: {e}")
            return None
    
    def _handle_client(self, client_socket: socket.socket, client_addr: Tuple[str, int]):
        """Handle client connection"""
        logger.info(f"Client connected: {client_addr}")
        
        try:
            while self.running:
                # Set a timeout to allow checking self.running
                client_socket.settimeout(1.0)
                
                try:
                    data = client_socket.recv(1024)
                    if not data:
                        break
                    
                    logger.debug(f"Received {len(data)} bytes from {client_addr}")
                    
                    response = self._process_request(data)
                    
                    if response is None:
                        # Simulate crash - close connection
                        logger.warning(f"Simulating crash - closing connection to {client_addr}")
                        break
                    elif response == b"":
                        # Simulate no response (timeout)
                        logger.warning(f"Simulating no response to {client_addr}")
                        continue
                    else:
                        client_socket.send(response)
                        logger.debug(f"Sent {len(response)} bytes to {client_addr}")
                
                except socket.timeout:
                    continue  # Check if still running
                except ConnectionResetError:
                    logger.info(f"Client {client_addr} reset connection")
                    break
                except Exception as e:
                    logger.error(f"Error handling client {client_addr}: {e}")
                    break
                    
        except Exception as e:
            logger.error(f"Client handler error for {client_addr}: {e}")
        finally:
            try:
                client_socket.close()
            except:
                pass
            logger.info(f"Client disconnected: {client_addr}")
            
            # Remove from connections list
            try:
                self.connections.remove(client_socket)
            except ValueError:
                pass
    
    def start_server(self):
        """Start the Modbus slave server"""
        try:
            server_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            server_socket.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
            server_socket.bind((self.host, self.port))
            server_socket.listen(10)
            
            self.running = True
            logger.info(f"Vulnerable Modbus slave started on {self.host}:{self.port}")
            logger.warning("WARNING: This server contains intentional vulnerabilities!")
            
            while self.running:
                try:
                    server_socket.settimeout(1.0)  # Allow checking self.running
                    client_socket, client_addr = server_socket.accept()
                    
                    self.connections.append(client_socket)
                    
                    # Handle each client in a separate thread
                    client_thread = threading.Thread(
                        target=self._handle_client,
                        args=(client_socket, client_addr),
                        daemon=True
                    )
                    client_thread.start()
                    
                except socket.timeout:
                    continue
                except Exception as e:
                    if self.running:
                        logger.error(f"Accept error: {e}")
                    
        except Exception as e:
            logger.error(f"Server error: {e}")
        finally:
            try:
                server_socket.close()
            except:
                pass
            
            # Close all client connections
            for conn in self.connections:
                try:
                    conn.close()
                except:
                    pass
            
            logger.info("Modbus slave server stopped")
    
    def stop_server(self):
        """Stop the server"""
        self.running = False
        logger.info("Stopping Modbus slave server...")
    
    def print_statistics(self):
        """Print server statistics"""
        print("\n" + "="*50)
        print("VULNERABLE MODBUS SLAVE STATISTICS")
        print("="*50)
        print(f"Requests handled: {self.requests_handled}")
        print(f"Exceptions sent: {self.exceptions_sent}")
        print(f"Crashes simulated: {self.crashes_simulated}")
        print(f"Coils: {sum(self.coils)} set out of {len(self.coils)}")
        print(f"Holding registers: {len([r for r in self.holding_registers if r != 0])} non-zero")
        print("="*50)

def main():
    """Main function"""
    import signal
    
    host = sys.argv[1] if len(sys.argv) > 1 else '0.0.0.0'
    port = int(sys.argv[2]) if len(sys.argv) > 2 else 502
    
    # Create vulnerable slave
    slave = VulnerableModbusSlave(host, port)
    
    # Signal handler for graceful shutdown
    def signal_handler(signum, frame):
        print("\nShutting down server...")
        slave.stop_server()
        slave.print_statistics()
        sys.exit(0)
    
    signal.signal(signal.SIGINT, signal_handler)
    signal.signal(signal.SIGTERM, signal_handler)
    
    print("="*60)
    print("VULNERABLE MODBUS TCP SLAVE SIMULATOR")
    print("="*60)
    print("WARNING: This server contains intentional vulnerabilities!")
    print("Use only for security testing and educational purposes.")
    print("="*60)
    print(f"Starting server on {host}:{port}")
    print("Press Ctrl+C to stop")
    print("="*60)
    
    try:
        slave.start_server()
    except KeyboardInterrupt:
        print("\nServer interrupted")
    finally:
        slave.stop_server()
        slave.print_statistics()

if __name__ == "__main__":
    main()
