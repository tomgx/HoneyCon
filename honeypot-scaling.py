import subprocess
import time
import os

COUNT_FILE = "syn_count.txt"
ACTIVE_FILE = "active_count.txt"
THRESHOLD = 20 
MAX_CONTAINERS = 50
running_containers = {}

def update_active_file():
    with open(ACTIVE_FILE, "w") as f: f.write(str(len(running_containers)))

def get_syn_count():
    try:
        with open(COUNT_FILE, 'r') as f:
            val = f.read().strip()
            return int(val) if val else 0
    except: return 0

def scale_up():
    if len(running_containers) >= MAX_CONTAINERS: return
    port = 2222 + len(running_containers)
    res = subprocess.run(['docker', 'run', '-d', '-p', f'{port}:2222', 'cowrie/cowrie:latest'], capture_output=True, text=True)
    if res.returncode == 0:
        running_containers[res.stdout.strip()] = port
        update_active_file()
        print(f"DEPLOYED: {res.stdout.strip()[:12]} on port {port}. Total: {len(running_containers)}")

def scale_down():
    if not running_containers: return
    c_id, port = running_containers.popitem()
    subprocess.run(['docker', 'stop', c_id], capture_output=True)
    subprocess.run(['docker', 'rm', c_id], capture_output=True)
    update_active_file()
    print(f"REMOVED: Honeypot on port {port}. Total: {len(running_containers)}")

if __name__ == '__main__':
    update_active_file()
    print(f"HoneyCon: SYN Threshold set to [{THRESHOLD}] SYN. Max [{MAX_CONTAINERS}] containers")
    while True:
        count = get_syn_count()
        print(f"SYN Count: {count} | Active Containers: {len(running_containers)}")
        
        if count >= THRESHOLD:
            scale_up()
        elif count == 0 and len(running_containers) > 0:
            # 3 second buffer so it doesn't scale down too aggressively
            time.sleep(3)
            if get_syn_count() == 0:
                scale_down()
        
        with open(COUNT_FILE, 'w') as f: f.write('0')
        time.sleep(1)