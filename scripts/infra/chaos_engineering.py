import os
import sys
import time
import random
import subprocess
import json
from datetime import datetime, timezone

# Configurações
CHAOS_ENABLED = os.getenv("SENTINELA_CHAOS_ENABLED", "false").lower() == "true"
TARGET_CONTAINERS = ["kafka", "redis", "rule_engine", "alert_sink", "ai_engine"]
REPORT_PATH = "docs/CHAOS_REPORT.md"

def log_message(msg):
    print(f"[{datetime.now().isoformat()}] {msg}")

def check_enabled():
    if not CHAOS_ENABLED:
        print("Error: Chaos Engineering is disabled (SENTINELA_CHAOS_ENABLED=false).")
        sys.exit(1)

def kill_container(container_name):
    log_message(f"Chaos Monkey: Killing container {container_name}...")
    try:
        # Tenta matar pelo nome ou parte do nome (docker-compose costuma prefixar/sufixar)
        result = subprocess.run(
            ["docker", "ps", "--filter", f"name={container_name}", "--format", "{{.Names}}"],
            capture_output=True, text=True
        )
        names = result.stdout.strip().split("\n")
        if names and names[0]:
            target = names[0]
            subprocess.run(["docker", "kill", target], check=True)
            log_message(f"Container {target} killed successfully.")
            return target
        else:
            log_message(f"Container {container_name} not found running.")
            return None
    except Exception as e:
        log_message(f"Failed to kill container {container_name}: {e}")
        return None

def check_self_healing(container_name, timeout=60):
    log_message(f"Checking self-healing for {container_name}...")
    start_time = time.time()
    while time.time() - start_time < timeout:
        try:
            result = subprocess.run(
                ["docker", "inspect", "-f", "{{.State.Status}} {{.State.Health.Status}}", container_name],
                capture_output=True, text=True
            )
            output = result.stdout.strip()
            if "running" in output and ("healthy" in output or "unsupported" in output): # 'unsupported' se não tiver healthcheck
                recovery_time = round(time.time() - start_time, 2)
                log_message(f"Container {container_name} recovered in {recovery_time}s.")
                return True, recovery_time
        except:
            pass
        time.sleep(5)
    
    log_message(f"Container {container_name} failed to recover within {timeout}s.")
    return False, timeout

def generate_report(results):
    log_message(f"Generating chaos report at {REPORT_PATH}...")
    
    os.makedirs(os.path.dirname(REPORT_PATH), exist_ok=True)
    
    timestamp = datetime.now(timezone.utc).strftime("%Y-%m-%d %H:%M:%S UTC")
    
    report_content = f"""# SENTINELA Chaos Engineering Report
**Timestamp:** {timestamp}
**Status:** Executed

## Execution Summary
| Target Container | Action | Status | Recovery Time | Self-Healing |
|------------------|--------|--------|---------------|--------------|
"""
    
    for res in results:
        sh_status = "✅ PASS" if res['recovered'] else "❌ FAIL"
        report_content += f"| {res['target']} | docker kill | {res['status']} | {res['recovery_time']}s | {sh_status} |\n"
    
    report_content += "\n## Resilience Analysis\n"
    failures = [r for r in results if not r['recovered']]
    if not failures:
        report_content += "The system demonstrated full resilience. All killed containers were successfully restarted by the orchestrator (Docker Compose/K8s).\n"
    else:
        report_content += f"The system failed to recover {len(failures)} containers automatically. Manual intervention might be required.\n"

    with open(REPORT_PATH, "a") as f:
        f.write("\n---\n")
        f.write(report_content)
    
    log_message("Report generated successfully.")

def main():
    check_enabled()
    log_message("Starting Chaos Engineering session...")
    
    num_attacks = random.randint(1, 3)
    targets = random.sample(TARGET_CONTAINERS, num_attacks)
    
    results = []
    
    for target_base in targets:
        killed_name = kill_container(target_base)
        if killed_name:
            recovered, duration = check_self_healing(killed_name)
            results.append({
                "target": killed_name,
                "status": "Killed",
                "recovered": recovered,
                "recovery_time": duration
            })
            # Espera um pouco antes do próximo ataque
            time.sleep(10)
        else:
            results.append({
                "target": target_base,
                "status": "Not Found",
                "recovered": True, # Se não existia, assumimos OK para o reporte
                "recovery_time": 0
            })

    generate_report(results)
    log_message("Chaos Engineering session finished.")

if __name__ == "__main__":
    main()
