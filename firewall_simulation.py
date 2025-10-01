import socket
import subprocess
from datetime import datetime
from tkinter import *
from tkinter import scrolledtext

class FirewallSimulator:
    def __init__(self):
        self.rules = {
            "blocked_ips": ["10.0.0.5"],
            "blocked_ports": [22],
            "allowed_protocols": ["TCP"]
        }
        self.log_file = "firewall_log.txt"
        self.setup_log()

    def setup_log(self):
        """Initialize log file with headers"""
        with open(self.log_file, "w") as f:
            f.write("=== Firewall Log ===\n")

    def log_event(self, event):
        timestamp = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
        log_entry = f"[{timestamp}] {event}"
        print(log_entry)  # Print to console
        with open(self.log_file, "a") as f:
            f.write(log_entry + "\n")

    def check_packet(self, ip, port, protocol):
        if ip in self.rules["blocked_ips"]:
            self.log_event(f"BLOCKED: Packet from IP {ip}")
            return False
        elif port in self.rules["blocked_ports"]:
            self.log_event(f"BLOCKED: Packet on port {port}")
            return False
        elif protocol not in self.rules["allowed_protocols"]:
            self.log_event(f"BLOCKED: Protocol {protocol} not allowed")
            return False
        else:
            self.log_event(f"ALLOWED: Packet from {ip}:{port} via {protocol}")
            return True

    def add_windows_firewall_rule(self, name, dir="in", action="block", protocol="TCP", port=""):
        """Add a rule to the real Windows Firewall using netsh"""
        cmd = f'netsh advfirewall firewall add rule name="{name}" dir={dir} action={action} protocol={protocol} localport={port}'
        try:
            subprocess.run(cmd, shell=True, check=True)
            self.log_event(f"Added Windows Firewall rule: {name}")
            return True
        except subprocess.CalledProcessError as e:
            self.log_event(f"Failed to add rule: {e}")
            return False

class FirewallGUI:
    def __init__(self, root):
        self.firewall = FirewallSimulator()
        self.root = root
        self.root.title("Firewall Simulator")
        self.root.geometry("500x400")

        # Main Frame
        main_frame = Frame(root)
        main_frame.pack(pady=10)

        # Rule Management Frame
        rule_frame = LabelFrame(main_frame, text="Add Block Rule")
        rule_frame.grid(row=0, column=0, padx=10, pady=5)

        # IP Blocking
        Label(rule_frame, text="IP Address:").grid(row=0, column=0, sticky=W)
        self.ip_entry = Entry(rule_frame, width=20)
        self.ip_entry.grid(row=0, column=1, padx=5)

        # Port Blocking
        Label(rule_frame, text="Port:").grid(row=1, column=0, sticky=W)
        self.port_entry = Entry(rule_frame, width=20)
        self.port_entry.grid(row=1, column=1, padx=5)

        # Protocol Selection
        Label(rule_frame, text="Protocol:").grid(row=2, column=0, sticky=W)
        self.protocol_var = StringVar(value="TCP")
        OptionMenu(rule_frame, self.protocol_var, "TCP", "UDP", "ICMP").grid(row=2, column=1, sticky=W+E)

        # Add Rule Button
        Button(rule_frame, text="Add Rule", command=self.add_rule).grid(row=3, columnspan=2, pady=5)

        # Windows Firewall Integration
        winfw_frame = LabelFrame(main_frame, text="Windows Firewall")
        winfw_frame.grid(row=1, column=0, padx=10, pady=5, sticky=W+E)

        Label(winfw_frame, text="Rule Name:").grid(row=0, column=0, sticky=W)
        self.rule_name_entry = Entry(winfw_frame, width=20)
        self.rule_name_entry.grid(row=0, column=1, padx=5)

        Button(winfw_frame, text="Add Windows Rule", command=self.add_windows_rule).grid(row=1, columnspan=2, pady=5)

        # Log Display
        log_frame = LabelFrame(main_frame, text="Firewall Logs")
        log_frame.grid(row=2, column=0, padx=10, pady=5, sticky=W+E+N+S)

        self.log_text = scrolledtext.ScrolledText(log_frame, width=60, height=10)
        self.log_text.pack()
        self.update_log()

        # Test Buttons
        test_frame = Frame(main_frame)
        test_frame.grid(row=3, column=0, pady=5)
        Button(test_frame, text="Test Blocked IP", command=lambda: self.test_packet("10.0.0.5", 80, "TCP")).pack(side=LEFT, padx=2)
        Button(test_frame, text="Test Blocked Port", command=lambda: self.test_packet("192.168.1.1", 22, "TCP")).pack(side=LEFT, padx=2)
        Button(test_frame, text="Test Allowed Packet", command=lambda: self.test_packet("8.8.8.8", 80, "TCP")).pack(side=LEFT, padx=2)

    def add_rule(self):
        ip = self.ip_entry.get()
        port = self.port_entry.get()
        protocol = self.protocol_var.get()

        if ip:
            self.firewall.rules["blocked_ips"].append(ip)
        if port:
            self.firewall.rules["blocked_ports"].append(int(port))
        if protocol:
            self.firewall.rules["allowed_protocols"] = [protocol]

        self.update_log()
        self.ip_entry.delete(0, END)
        self.port_entry.delete(0, END)

    def add_windows_rule(self):
        name = self.rule_name_entry.get()
        if name:
            success = self.firewall.add_windows_firewall_rule(name)
            if success:
                self.rule_name_entry.delete(0, END)
        self.update_log()

    def test_packet(self, ip, port, protocol):
        self.firewall.check_packet(ip, port, protocol)
        self.update_log()

    def update_log(self):
        try:
            with open(self.firewall.log_file, "r") as f:
                logs = f.read()
            self.log_text.delete(1.0, END)
            self.log_text.insert(END, logs)
        except FileNotFoundError:
            self.log_text.delete(1.0, END)
            self.log_text.insert(END, "Log file not found.")

if __name__ == "__main__":
    root = Tk()
    app = FirewallGUI(root)
    root.mainloop()