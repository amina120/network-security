Project Report: Network Security Scanner & Firewall Visualizer1. 
Introduction
The Network Security Scanner & Firewall Visualizer is a comprehensive local lab application designed to simulate network reconnaissance, active port scanning, and priority-based packet filtering/firewall rule enforcement. The system provides a web-based dashboard allowing users to target hosts, inspect port states, configure custom firewall rules, and analyze traffic drop decisions in real-time.
2. Technical Stack & ArchitectureBackend: Python Flask framework running locally on port 5001 ([http://127.0.0.1:5001](http://127.0.0.1:5001)).  
Frontend: Responsive HTML/CSS/JavaScript dashboard featuring jQuery for asynchronous API communication.
Core Modules:Rule Engine: Priority-based packet filtering supporting ALLOW and DENY actions, IP/CIDR matching, port range specifications, and protocol filtering (tcp, udp, any).
Simulation & Enforcement Layer: Multi-threaded local socket lab services running dynamically on ports 8081–8084 and 9091 that bind or unbind based on active firewall verdicts.
Scanner Engine: Robust port parser and socket-based active connection probes to verify traffic states (open, blocked) instantly.
3. Key Features & FunctionalityDynamic Firewall Rules Management: Users can define custom security policies with explicit priority ordering (lower numeric values indicate higher priority). The engine evaluates rules sequentially and falls back to a configurable default policy (ALLOW).
Active Traffic Enforcement: When a port is denied by a firewall rule, the scanner immediately intercepts the probe and flags the traffic as blocked alongside the exact triggering rule ID.Real-time Visual Feedback: Clean, structured tables display scan summaries, target status, service names, and decision reasoning for each probed port.
4. ConclusionThis project successfully demonstrates foundational network security concepts, packet inspection workflows, and firewall rule evaluation logic within a controlled local environment.
