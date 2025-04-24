import streamlit as st
import subprocess
import os
import time
import threading
from streamlit.runtime.scriptrunner import add_script_run_ctx

# Path to your client executable
CLIENT_EXECUTABLE = "/home/rapid/ssl_project_c/src/client_robot"
SERVER_IP_DEFAULT = "192.168.1.100"  # Default server IP

def initialize_session_state():
    """Initialize all session state variables"""
    if 'executing' not in st.session_state:
        st.session_state.executing = False
    if 'status_message' not in st.session_state:
        st.session_state.status_message = ""
    if 'command_history' not in st.session_state:
        st.session_state.command_history = []
    if 'server_ip' not in st.session_state:
        st.session_state.server_ip = SERVER_IP_DEFAULT

def execute_client_command(command):
    """Execute the client with specific command"""
    if st.session_state.executing:
        st.warning("A command is already being executed. Please wait.")
        return
    
    st.session_state.executing = True
    st.session_state.status_message = f"Executing: {command}"
    
    try:
        # Set the command as an environment variable and execute the client
        env = os.environ.copy()
        env["COMMAND"] = command
        
        process = subprocess.Popen(
            [CLIENT_EXECUTABLE, st.session_state.server_ip],
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            text=True,
            env=env
        )
        
        stdout, stderr = process.communicate()
        
        if process.returncode == 0:
            st.session_state.status_message = f"Completed: {command}"
            st.session_state.command_history.append({
                "command": command,
                "status": "Success",
                "time": time.strftime("%H:%M:%S"),
                "output": stdout.strip()
            })
        else:
            st.session_state.status_message = f"Failed: {command}. Error: {stderr}"
            st.session_state.command_history.append({
                "command": command,
                "status": "Failed",
                "time": time.strftime("%H:%M:%S"),
                "output": stderr.strip()
            })
        
    except Exception as e:
        st.error(f"Error executing command: {str(e)}")
        st.session_state.command_history.append({
            "command": command,
            "status": "Error",
            "time": time.strftime("%H:%M:%S"),
            "output": str(e)
        })
    
    finally:
        st.session_state.executing = False
        st.rerun()

def main():
    st.set_page_config(page_title="Robot Arm Control", layout="wide")
    initialize_session_state()
    
    st.title("Robot Arm Control System")
    st.subheader("Control interface for your secure robotic arm")
    
    # Server configuration
    st.sidebar.header("Server Configuration")
    st.session_state.server_ip = st.sidebar.text_input("Server IP Address", st.session_state.server_ip)
    
    # Verify client executable exists
    if not os.path.exists(CLIENT_EXECUTABLE):
        st.sidebar.error(f"Client executable not found at:\n{CLIENT_EXECUTABLE}")
    
    # Control buttons
    st.header("Robot Control Panel")
    col1, col2, col3 = st.columns(3)
    
    with col1:
        if st.button("Spin 90°", disabled=st.session_state.executing):
            thread = threading.Thread(
                target=execute_client_command,
                args=("spin ninety",),
                daemon=True
            )
            add_script_run_ctx(thread)
            thread.start()
    
    with col2:
        if st.button("Spin 180°", disabled=st.session_state.executing):
            thread = threading.Thread(
                target=execute_client_command,
                args=("spin oneeighty",),
                daemon=True
            )
            add_script_run_ctx(thread)
            thread.start()
    
    with col3:
        if st.button("Rest Position", disabled=st.session_state.executing):
            thread = threading.Thread(
                target=execute_client_command,
                args=("rest",),
                daemon=True
            )
            add_script_run_ctx(thread)
            thread.start()
    
    # Status display
    if st.session_state.status_message:
        st.info(st.session_state.status_message)
    
    if st.session_state.executing:
        st.warning("Command in progress... Please wait.")
        time.sleep(0.1)
        st.rerun()
    
    # Command history
    st.header("Command History")
    if st.session_state.command_history:
        # Display more detailed history including outputs
        for item in reversed(st.session_state.command_history):
            with st.expander(f"{item['time']} - {item['command']} ({item['status']})"):
                st.text(item.get('output', 'No output'))
    else:
        st.write("No commands executed yet.")
    
    if st.button("Clear History"):
        st.session_state.command_history = []
        st.rerun()

if __name__ == "__main__":
    main()
