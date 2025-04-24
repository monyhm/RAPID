# robot_interface.py
import streamlit as st
import subprocess
import os
import time
import threading

# Path to your client executable - update this to match your setup
CLIENT_EXECUTABLE = "/path/to/your/client_executable"
SERVER_IP_DEFAULT = "192.168.1.100"  # Default server IP

# Initialize session state
if 'executing' not in st.session_state:
    st.session_state.executing = False
if 'status_message' not in st.session_state:
    st.session_state.status_message = ""
if 'command_history' not in st.session_state:
    st.session_state.command_history = []

def execute_client_command(command):
    """Execute the client with specific command"""
    # Make sure the client isn't already running
    if st.session_state.executing:
        st.warning("A command is already being executed. Please wait.")
        return
    
    st.session_state.executing = True
    
    try:
        # Create a temporary script that will run your client code with the command
        script_path = "/tmp/robot_command.sh"
        with open(script_path, "w") as f:
            f.write(f"""#!/bin/bash
# This script executes a single robot command
export COMMAND="{command}"
cd {os.path.dirname(CLIENT_EXECUTABLE)}
{CLIENT_EXECUTABLE} {st.session_state.server_ip}
""")
        
        # Make the script executable
        os.chmod(script_path, 0o755)
        
        # Execute the command and capture output
        st.session_state.status_message = f"Executing: {command}"
        
        process = subprocess.Popen(
            script_path, 
            stdout=subprocess.PIPE, 
            stderr=subprocess.PIPE,
            text=True
        )
        
        stdout, stderr = process.communicate()
        
        if process.returncode == 0:
            st.session_state.status_message = f"Completed: {command}"
            st.session_state.command_history.append({
                "command": command,
                "status": "Success",
                "time": time.strftime("%H:%M:%S")
            })
        else:
            st.session_state.status_message = f"Failed: {command}. Error: {stderr}"
            st.session_state.command_history.append({
                "command": command,
                "status": "Failed",
                "time": time.strftime("%H:%M:%S")
            })
        
    except Exception as e:
        st.error(f"Error executing command: {str(e)}")
        st.session_state.command_history.append({
            "command": command,
            "status": "Error",
            "time": time.strftime("%H:%M:%S")
        })
    
    finally:
        st.session_state.executing = False

# Streamlit UI
def main():
    st.set_page_config(page_title="Robot Arm Control", layout="wide")
    
    # Title and description
    st.title("Robot Arm Control System")
    st.subheader("Control interface for your secure robotic arm")
    
    # Server IP configuration
    if 'server_ip' not in st.session_state:
        st.session_state.server_ip = SERVER_IP_DEFAULT
    
    st.sidebar.header("Server Configuration")
    st.session_state.server_ip = st.sidebar.text_input("Server IP Address", st.session_state.server_ip)
    
    # Add a check to see if the client executable exists
    if not os.path.exists(CLIENT_EXECUTABLE):
        st.sidebar.error(f"Client executable not found at:\n{CLIENT_EXECUTABLE}\nPlease update the path in the script.")
    
    # Robot control panel
    st.header("Robot Control Panel")
    
    # Individual command buttons
    st.subheader("Individual Commands")
    col1, col2, col3 = st.columns(3)
    
    with col1:
        if st.button("Spin 90°", disabled=st.session_state.executing):
            # Create a thread to avoid blocking the UI
            threading.Thread(
                target=execute_client_command,
                args=("spin ninety",),
                daemon=True
            ).start()
    
    with col2:
        if st.button("Spin 180°", disabled=st.session_state.executing):
            threading.Thread(
                target=execute_client_command,
                args=("spin oneeighty",),
                daemon=True
            ).start()
    
    with col3:
        if st.button("Rest Position", disabled=st.session_state.executing):
            threading.Thread(
                target=execute_client_command,
                args=("rest",),
                daemon=True
            ).start()
    
    # Status message
    if st.session_state.status_message:
        st.info(st.session_state.status_message)
    
    # Display execution status
    if st.session_state.executing:
        st.warning("Command in progress... Please wait.")
    
    # Command history
    st.header("Command History")
    if st.session_state.command_history:
        history_df = st.dataframe(
            st.session_state.command_history,
            use_container_width=True
        )
    else:
        st.write("No commands executed yet.")
    
    # Clear history button
    if st.button("Clear History"):
        st.session_state.command_history = []

if __name__ == "__main__":
    main()
