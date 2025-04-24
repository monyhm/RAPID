# robot_control_app.py
import streamlit as st
import subprocess
import os
import sys
import time
import threading
import socket
import ssl
import hashlib
from functools import wraps

# Add your SSL certificate paths
CERT_FILE = "../certs/client.crt"
KEY_FILE = "../certs/client.key"
CA_FILE = "../certs/ca.crt"
PORT = 8888  # Same port as in your C code

# Global connection variables
ssl_socket = None
connected = False
server_ip = ""

# Initialize session state for connection status
if 'connected' not in st.session_state:
    st.session_state.connected = False
if 'executing' not in st.session_state:
    st.session_state.executing = False
if 'status_message' not in st.session_state:
    st.session_state.status_message = ""

def secure_connection(func):
    """Decorator to ensure SSL connection is established before operations"""
    @wraps(func)
    def wrapper(*args, **kwargs):
        if not st.session_state.connected:
            st.error("Not connected to server. Please connect first.")
            return None
        return func(*args, **kwargs)
    return wrapper

def connect_to_server(ip_address):
    """Establish SSL connection to the server"""
    global ssl_socket, connected, server_ip
    
    try:
        # Create a socket and connect
        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        sock.connect((ip_address, PORT))
        
        # Set up SSL context
        context = ssl.create_default_context(ssl.Purpose.SERVER_AUTH)
        context.load_cert_chain(certfile=CERT_FILE, keyfile=KEY_FILE)
        context.load_verify_locations(cafile=CA_FILE)
        context.check_hostname = False
        
        # Wrap socket with SSL
        ssl_socket = context.wrap_socket(sock, server_hostname=ip_address)
        
        # Send initial hash to verify
        initial_hash = calculate_program_hash()
        if send_hash(initial_hash, is_initial=True):
            st.session_state.connected = True
            st.session_state.status_message = f"Connected to server at {ip_address}"
            server_ip = ip_address
            return True
        else:
            ssl_socket.close()
            st.session_state.status_message = "Hash verification failed"
            return False
            
    except Exception as e:
        st.session_state.status_message = f"Connection failed: {str(e)}"
        return False

def disconnect_from_server():
    """Close the SSL connection"""
    global ssl_socket
    if ssl_socket:
        try:
            ssl_socket.close()
        except:
            pass
    st.session_state.connected = False
    st.session_state.status_message = "Disconnected from server"

def calculate_program_hash():
    """Simulate the hash calculation from the C code
    In a real implementation, this would calculate hash based on your program's logic
    """
    # This is a placeholder - you'll need to implement the actual hashing logic
    # that matches your C implementation
    sample_hash = "bdf8a74d05ac5624973bf2b93b483961b1ca55206438b43199751265654234b1"
    return sample_hash

def send_hash(hash_value, is_initial=False):
    """Send hash to server for verification"""
    global ssl_socket
    hash_type = "INIT" if is_initial else "PERIODIC"
    message = f"HASH:{hash_type}:{hash_value}"
    
    try:
        ssl_socket.send(message.encode())
        response = ssl_socket.recv(1024).decode()
        return response.startswith("HASH_OK")
    except Exception as e:
        st.error(f"Hash sending failed: {e}")
        return False

@secure_connection
def send_command(command):
    """Send command to server and update hash"""
    global ssl_socket
    
    try:
        # Send the command
        ssl_socket.send(command.encode())
        
        # Wait for acknowledgment
        response = ssl_socket.recv(1024).decode()
        
        # After executing command, send updated hash
        updated_hash = calculate_program_hash()
        send_hash(updated_hash, is_initial=False)
        
        return response.startswith("COMMAND_ACK")
    except Exception as e:
        st.error(f"Command failed: {e}")
        return False

def execute_spin_ninety():
    st.session_state.executing = True
    st.session_state.status_message = "Executing: Spin 90 degrees"
    success = send_command("spin ninety")
    time.sleep(1)  # Simulate execution time
    st.session_state.status_message = "Completed: Spin 90 degrees" if success else "Failed: Spin 90 degrees"
    st.session_state.executing = False

def execute_spin_oneeighty():
    st.session_state.executing = True
    st.session_state.status_message = "Executing: Spin 180 degrees"
    success = send_command("spin oneeighty")
    time.sleep(1)  # Simulate execution time
    st.session_state.status_message = "Completed: Spin 180 degrees" if success else "Failed: Spin 180 degrees"
    st.session_state.executing = False

def execute_rest():
    st.session_state.executing = True
    st.session_state.status_message = "Executing: Rest position"
    success = send_command("rest")
    time.sleep(1)  # Simulate execution time
    st.session_state.status_message = "Completed: Rest position" if success else "Failed: Rest position"
    st.session_state.executing = False

def execute_sequence():
    st.session_state.executing = True
    st.session_state.status_message = "Executing sequence..."
    
    # Execute the full sequence
    success1 = send_command("spin ninety")
    time.sleep(1)
    
    success2 = send_command("spin oneeighty")
    time.sleep(1)
    
    success3 = send_command("rest")
    
    if success1 and success2 and success3:
        st.session_state.status_message = "Sequence completed successfully"
    else:
        st.session_state.status_message = "Sequence failed"
    
    st.session_state.executing = False

# Streamlit UI
def main():
    st.set_page_config(page_title="Robot Arm Control", layout="wide")
    
    # Title and description
    st.title("Secure Robot Arm Control System")
    st.subheader("Control interface for robotic arm with security features")
    
    # Server connection panel
    st.sidebar.header("Server Connection")
    server_ip = st.sidebar.text_input("Server IP Address", "192.168.1.100")
    
    col1, col2 = st.sidebar.columns(2)
    with col1:
        connect_button = st.button("Connect", disabled=st.session_state.connected)
    with col2:
        disconnect_button = st.button("Disconnect", disabled=not st.session_state.connected)
    
    # Connection status
    status_color = "green" if st.session_state.connected else "red"
    status_text = "Connected" if st.session_state.connected else "Disconnected"
    st.sidebar.markdown(f"<h4>Status: <span style='color:{status_color}'>{status_text}</span></h4>", unsafe_allow_html=True)
    
    # Handle connection/disconnection
    if connect_button:
        if connect_to_server(server_ip):
            st.sidebar.success("Connected successfully!")
        else:
            st.sidebar.error("Connection failed!")
    
    if disconnect_button:
        disconnect_from_server()
        st.sidebar.info("Disconnected from server")
    
    # Robot control panel
    st.header("Robot Control Panel")
    
    # Individual command buttons
    st.subheader("Individual Commands")
    col1, col2, col3 = st.columns(3)
    
    with col1:
        if st.button("Spin 90°", disabled=not st.session_state.connected or st.session_state.executing):
            execute_spin_ninety()
    
    with col2:
        if st.button("Spin 180°", disabled=not st.session_state.connected or st.session_state.executing):
            execute_spin_oneeighty()
    
    with col3:
        if st.button("Rest Position", disabled=not st.session_state.connected or st.session_state.executing):
            execute_rest()
    
    # Full sequence button
    st.subheader("Execute Full Sequence")
    if st.button("Run Complete Sequence", disabled=not st.session_state.connected or st.session_state.executing):
        execute_sequence()
    
    # Status message
    if st.session_state.status_message:
        st.info(st.session_state.status_message)
    
    # Display execution status
    if st.session_state.executing:
        st.warning("Command in progress... Please wait.")
    
    # Security information
    st.sidebar.header("Security Information")
    st.sidebar.info("""
    This interface uses:
    - SSL/TLS encryption
    - Certificate verification
    - Hash-based integrity verification
    - Secure command execution
    """)

if __name__ == "__main__":
    main()
