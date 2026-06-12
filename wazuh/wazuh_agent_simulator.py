import os
import time
import json
from pathlib import Path

class WazuhAgentSimulator:
    def __init__(self, log_path="data/mysql_audit.log", callback_fn=None):
        self.log_path = Path(log_path)
        self.callback = callback_fn
        self.running = False

    def start(self):
        """Starts monitoring the log file and shipping new logs."""
        print(f"[*] Wazuh Agent Simulator started. Monitoring: {self.log_path}")
        self.running = True
        
        # Ensure log file exists
        if not self.log_path.exists():
            os.makedirs(self.log_path.parent, exist_ok=True)
            with open(self.log_path, "w") as f:
                pass # Create empty file

        with open(self.log_path, "r", encoding="utf-8") as f:
            # Seek to the end of the file to only monitor new entries
            f.seek(0, 2)
            
            while self.running:
                line = f.readline()
                if not line or not line.strip():
                    time.sleep(0.1) # Sleep briefly to prevent high CPU usage
                    continue
                
                try:
                    log_entry = json.loads(line.strip())
                    if self.callback:
                        self.callback(log_entry)
                    else:
                        print(f"[Wazuh Agent Shipper] Forwarded log: {log_entry.get('username')} -> {log_entry.get('query_type')}")
                except json.JSONDecodeError:
                    print(f"[Wazuh Agent Shipper] [!] Failed to decode log line: {line}")
                except Exception as e:
                    print(f"[Wazuh Agent Shipper] [!] Error shipping log: {e}")

    def stop(self):
        """Stops the log shipper."""
        print("[*] Stopping Wazuh Agent Simulator...")
        self.running = False
        
if __name__ == "__main__":
    # Test standalone agent
    agent = WazuhAgentSimulator()
    try:
        agent.start()
    except KeyboardInterrupt:
        agent.stop()
