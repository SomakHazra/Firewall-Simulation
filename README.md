Firewall Simulator with GUI
A simple desktop application built with Python and Tkinter to simulate the basic functionalities of a network firewall. This tool provides a graphical user interface to add blocking rules, test packet filtering, and view real-time logs. It also includes an experimental feature to add rules directly to the Windows Defender Firewall.
Features
●	Simple GUI: Easy-to-use interface built with Python's native Tkinter library.
●	Rule-Based Filtering: Simulates packet filtering based on:
○	Source IP Address
○	Destination Port
○	Protocol (TCP, UDP, ICMP)
●	Real-time Logging: All actions (allowed packets, blocked packets, new rules) are timestamped and displayed in the log window and saved to firewall_log.txt.
●	Packet Simulation: Test your rules with dedicated buttons to simulate traffic from blocked IPs, blocked ports, or allowed sources.
●	Windows Firewall Integration: Ability to add a new inbound rule directly to the native Windows Firewall using the netsh command.
How to Use
Prerequisites
●	Python 3.x
●	Windows Operating System (for the Windows Firewall integration feature)
Running the Application
1.	Clone the repository or download the script.
2.	Navigate to the project directory in your terminal.
3.	Run the script using the following command:
python firewall_simulator.py


Functionality Explained
1. The Simulator
The core of the application simulates a firewall's logic. You can add rules to block specific IPs or ports.
●	Adding a Rule: Enter an IP address or a port number and click "Add Rule". The simulator will update its internal ruleset.
●	Testing Packets: Use the "Test" buttons to simulate an incoming network packet. The application checks the packet's details (IP, port, protocol) against its rules and logs whether it would be ALLOWED or BLOCKED.
2. Windows Firewall Integration
This feature allows the application to interact with the actual Windows Defender Firewall.
●	How it works: It constructs and executes a netsh advfirewall firewall add rule command based on the rule name you provide.
●	Important: To successfully add a rule to the Windows Firewall, you must run the Python script with administrator privileges. To do this, open your command prompt or PowerShell as an Administrator and then run the script.
Dependencies
This script uses only Python's standard libraries, so no external packages need to be installed.
●	tkinter
●	socket
●	subprocess
●	datetime
License
This project is licensed under the MIT License. See the LICENSE file for details.
