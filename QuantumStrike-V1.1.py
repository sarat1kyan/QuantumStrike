import argparse
import os
import subprocess
import requests
import asyncio
from fpdf import FPDF
from rich.console import Console
import questionary
from pymetasploit3.msfrpc import MsfRpcClient
import matplotlib.pyplot as plt
import re

console = Console()

CONFIG = {
    "api_keys": {
        "vulners": "W57LC0I5F1GE9ZRP0IQN4OVCJJ7878JTKPUN7RQWVR6NZP87VHP77PT6381POYDD",
        "chatgpt": "your_openai_api_key",
    },
    "metasploit": {
        "username": "msf",
        "password": "msfpass",
    },
    "output_dir": "output",
}
os.makedirs(CONFIG["output_dir"], exist_ok=True)


def banner():
    console.print(
        "[bold blue]"
        " ██████╗ ██╗   ██╗ █████╗ ███╗   ██╗████████╗██╗   ██╗███╗   ███╗███████╗████████╗██████╗ ██╗██╗  ██╗███████╗\n"
        "██╔═══██╗██║   ██║██╔══██╗████╗  ██║╚══██╔══╝██║   ██║████╗ ████║██╔════╝╚══██╔══╝██╔══██╗██║██║ ██╔╝██╔════╝\n"
        "██║   ██║██║   ██║███████║██╔██╗ ██║   ██║   ██║   ██║██╔████╔██║███████╗   ██║   ██████╔╝██║█████╔╝ █████╗  \n"
        "██║▄▄ ██║██║   ██║██╔══██║██║╚██╗██║   ██║   ██║   ██║██║╚██╔╝██║╚════██║   ██║   ██╔══██╗██║██╔═██╗ ██╔══╝  \n"
        "╚██████╔╝╚██████╔╝██║  ██║██║ ╚████║   ██║   ╚██████╔╝██║ ╚═╝ ██║███████║   ██║   ██║  ██║██║██║  ██╗███████╗\n"
        " ╚══▀▀═╝  ╚═════╝ ╚═╝  ╚═╝╚═╝  ╚═══╝   ╚═╝    ╚═════╝ ╚═╝     ╚═╝╚══════╝   ╚═╝   ╚═╝  ╚═╝╚═╝╚═╝  ╚═╝╚══════╝\n"
        "[bold yellow]Version 4.0 - QuantumStrike Beta Version 1.1[/bold yellow]"
    )


def execute_command(command):
    try:
        result = subprocess.run(command, capture_output=True, text=True)
        return result.stdout
    except Exception as e:
        console.print(f"[red]Error executing command: {e}[/red]")
        return None

def parse_nmap(output):
    parsed = []
    lines = output.split("\n")
    for line in lines:
        match = re.search(r"(\d+/tcp)\s+(\w+)\s+(.+)", line)
        if match:
            parsed.append({
                "port": match.group(1),
                "state": match.group(2),
                "service": match.group(3),
            })
    return parsed

def parse_masscan(output):
    parsed = []
    lines = output.split("\n")
    for line in lines:
        match = re.search(r"Discovered open port (\d+)/tcp on (\d+\.\d+\.\d+\.\d+)", line)
        if match:
            parsed.append({
                "port": match.group(1),
                "ip": match.group(2),
            })
    return parsed

def parse_amass(output):
    return [line.strip() for line in output.split("\n") if line.strip()]

def summarize_scan_results(scan_data):
    summary = []
    for tool, results in scan_data.items():
        if tool == "nmap":
            summary.append(f"Nmap discovered {len(results)} services:")
            for res in results:
                summary.append(f"- {res['port']} ({res['service']}) is {res['state']}")
        elif tool == "masscan":
            summary.append(f"Masscan discovered {len(results)} open ports:")
            for res in results:
                summary.append(f"- Port {res['port']} open on {res['ip']}")
        elif tool == "amass":
            summary.append(f"Amass discovered {len(results)} subdomains:")
            summary.extend(f"- {res}" for res in results)
    return "\n".join(summary)

def interactive_target_specific_scanning():
    target_type = questionary.select(
        "What type of target are you scanning?",
        choices=["Web Application", "Server", "Network"],
    ).ask()

    scan_data = {}
    
    if target_type == "Web Application":
        domain = questionary.text("Enter the website domain:").ask()
        subdomains = parse_amass(amass_scan(domain))
        live_websites = parse_amass(httprobe_scan(subdomains))
        vulnerabilities = [parse_nmap(nuclei_scan(site)) for site in live_websites]
        scan_data = {
            "subdomains": subdomains,
            "live_websites": live_websites,
            "vulnerabilities": vulnerabilities,
        }
    
    elif target_type == "Server":
        domain = questionary.text("Enter the server IP or domain:").ask()
        nmap_results = parse_nmap(nmap_scan(domain))
        dns_results = parse_amass(dnsrecon_scan(domain))
        scan_data = {
            "nmap": nmap_results,
            "dns": dns_results,
        }
    
    elif target_type == "Network":
        network = questionary.text("Enter the network range (e.g., 192.168.1.0/24):").ask()
        masscan_results = parse_masscan(masscan_scan(network))
        scan_data = {
            "masscan": masscan_results,
        }
    
    summary = summarize_scan_results(scan_data)
    console.print(summary)
    generate_detailed_scan_report(scan_data)

def nmap_scan(domain):
    return execute_command(["nmap", "-A", domain])

def nikto_scan(domain):
    return execute_command(["nikto", "-host", domain])

def whatweb_scan(domain):
    return execute_command(["whatweb", domain])

def sslyze_scan(domain):
    return execute_command(["sslyze", "--regular", domain])

def dns_enum(domain):
    return execute_command(["dnsenum", domain])

def gobuster_scan(domain, wordlist, mode="dir"):
    command = ["gobuster", mode, "-u", domain, "-w", wordlist]
    if mode == "dns":
        command += ["--dns-server", "8.8.8.8"]
    return execute_command(command)

def masscan_scan(network, ports="1-65535"):
    return execute_command(["masscan", network, "-p", ports, "--rate", "1000"])

def amass_scan(domain):
    return execute_command(["amass", "enum", "-passive", "-d", domain])

def nuclei_scan(domain, templates="default"):
    return execute_command(["nuclei", "-u", domain, "-t", templates])

def httprobe_scan(domains):
    with open("temp_domains.txt", "w") as f:
        f.writelines(f"{domain}\n" for domain in domains)
    return execute_command(["cat", "temp_domains.txt", "|", "httprobe"])

def dnsrecon_scan(domain):
    return execute_command(["dnsrecon", "-d", domain, "-t", "axfr"])

def subfinder_scan(domain):
    return execute_command(["subfinder", "-d", domain])

def enhanced_scanning_workflow(domain, network):
    subdomains = amass_scan(domain).split("\n")
    live_websites = httprobe_scan(subdomains).split("\n")
    dns_results = dnsrecon_scan(domain)
    masscan_results = masscan_scan(network)
    web_vulns = [nuclei_scan(website) for website in live_websites if website]
    return {
        "subdomains": subdomains,
        "live_websites": live_websites,
        "dns": dns_results,
        "network_scan": masscan_results,
        "web_vulnerabilities": web_vulns,
    }

def metasploit_setup():
    try:
        client = MsfRpcClient(CONFIG["metasploit"]["password"], username=CONFIG["metasploit"]["username"], ssl=False)
        return client
    except Exception as e:
        console.print(f"[red]Failed to connect to Metasploit RPC: {e}[/red]")
        return None

def metasploit_exploit(client, cve_id, target):
    modules = client.modules.search(cve_id)
    if not modules:
        return
    exploit = next((mod for mod in modules if mod['type'] == 'exploit'), None)
    if not exploit:
        return
    exploit_module = client.modules.use('exploit', exploit['fullname'])
    exploit_module['RHOSTS'] = target
    payload = exploit_module.targetpayloads()[0]
    payload_module = client.modules.use('payload', payload)
    client.jobs.run_module_with_output(exploit_module, payload_module)

def vulners_lookup(service_name, version):
    url = f"https://vulners.com/api/v3/search/lucene/"
    query = f"{service_name} {version}"
    headers = {"Content-Type": "application/json"}
    params = {"apiKey": CONFIG["api_keys"]["vulners"], "query": query, "size": 5}
    try:
        response = requests.get(url, headers=headers, params=params)
        if response.status_code == 200:
            vulns = response.json().get("data", {}).get("documents", [])
            return [vuln["id"] for vuln in vulns]
    except Exception:
        return []

async def async_scan(target, tool):
    if tool == "nmap":
        return target, tool, execute_command(["nmap", "-A", target])
    elif tool == "nikto":
        return target, tool, execute_command(["nikto", "-host", target])
    return target, tool, None

async def batch_scan(targets, tools):
    tasks = [async_scan(target, tool) for target in targets for tool in tools]
    return await asyncio.gather(*tasks)

def get_cvss_score(cve_id):
    url = f"https://services.nvd.nist.gov/rest/json/cve/1.0/{cve_id}"
    try:
        response = requests.get(url)
        if response.status_code == 200:
            data = response.json()
            metrics = data.get("impact", {}).get("baseMetricV3", {}).get("cvssV3", {})
            return metrics.get("baseScore", "N/A"), metrics.get("baseSeverity", "N/A")
    except Exception as e:
        console.print(f"[red]Error fetching CVSS score for {cve_id}: {e}[/red]")
    return "N/A", "N/A"

def prioritize_vulnerabilities(vulnerabilities):
    prioritized = []
    for vuln in vulnerabilities:
        score, severity = get_cvss_score(vuln)
        prioritized.append((vuln, score, severity))
    prioritized.sort(key=lambda x: x[1], reverse=True)
    return prioritized

def detailed_vulnerability_report(vulnerabilities):
    report = []
    for vuln, score, severity in vulnerabilities:
        report.append(f"{vuln} - CVSS: {score} ({severity})")
    return "\n".join(report)

def zap_scan(domain):
    return execute_command(["zap-cli", "scan", domain])

def wapiti_scan(domain):
    return execute_command(["wapiti", "-u", domain])

def multi_target_exploitation(targets, tools):
    results = asyncio.run(batch_scan(targets, tools))
    consolidated_report = {}
    for target, tool, output in results:
        if target not in consolidated_report:
            consolidated_report[target] = {}
        consolidated_report[target][tool] = output
    return consolidated_report

def unified_report(report_data):
    pdf = FPDF()
    pdf.add_page()
    pdf.set_font("Arial", size=12)
    pdf.cell(200, 10, txt="Unified Penetration Test Report", ln=True, align="C")
    for target, data in report_data.items():
        pdf.cell(200, 10, txt=f"Target: {target}", ln=True)
        for tool, output in data.items():
            pdf.cell(200, 10, txt=f"Tool: {tool}", ln=True)
            pdf.multi_cell(0, 10, output or "No results")
    pdf.output(os.path.join(CONFIG["output_dir"], "unified_report.pdf"))

def generate_vulnerability_graph(vulnerabilities):
    services = [v['service'] for v in vulnerabilities if 'service' in v]
    ports = [v['port'] for v in vulnerabilities if 'port' in v]

    plt.figure(figsize=(10, 6))
    plt.barh(services, [int(p.split('/')[0]) for p in ports], color='skyblue')
    plt.xlabel('Port Number')
    plt.ylabel('Service')
    plt.title('Vulnerability Distribution by Service')
    plt.tight_layout()
    filepath = os.path.join(CONFIG["output_dir"], "vulnerability_chart.png")
    plt.savefig(filepath)
    console.print(f"[bold green]Vulnerability chart saved at {filepath}[/bold green]")

def generate_advanced_report(target, scan_data):
    pdf = FPDF()
    pdf.add_page()
    pdf.set_font("Arial", size=12)
    pdf.cell(200, 10, txt=f"Advanced Penetration Testing Report: {target}", ln=True, align="C")

    for section, results in scan_data.items():
        pdf.cell(200, 10, txt=section.upper(), ln=True)
        if isinstance(results, list):
            for res in results:
                pdf.multi_cell(0, 10, str(res))
        else:
            pdf.multi_cell(0, 10, results)

    filepath = os.path.join(CONFIG["output_dir"], f"{target}_advanced_report.pdf")
    pdf.output(filepath)
    console.print(f"[bold green]Detailed report saved to {filepath}[/bold green]")

def generate_vulnerability_chart(vulnerabilities):
    labels = [vuln for vuln, score, severity in vulnerabilities]
    scores = [score for _, score, _ in vulnerabilities]

    plt.figure(figsize=(10, 6))
    plt.barh(labels, scores, color='skyblue')
    plt.xlabel('CVSS Scores')
    plt.ylabel('Vulnerabilities')
    plt.title('Vulnerability Severity')
    plt.tight_layout()
    plt.savefig(os.path.join(CONFIG["output_dir"], "vulnerability_chart.png"))

def ai_analysis(scan_results):
    openai_api_key = CONFIG["api_keys"]["chatgpt"]
    headers = {"Authorization": f"Bearer {openai_api_key}", "Content-Type": "application/json"}
    prompt = f"Analyze the following scan results for vulnerabilities:\n{scan_results}"
    payload = {"model": "text-davinci-003", "prompt": prompt, "max_tokens": 300}
    try:
        response = requests.post("https://api.openai.com/v1/completions", headers=headers, json=payload)
        if response.status_code == 200:
            return response.json().get("choices", [])[0].get("text", "").strip()
    except Exception:
        return "AI analysis failed."

def generate_report(target, scan_results, vulnerabilities, ai_suggestions):
    pdf = FPDF()
    pdf.add_page()
    pdf.set_font("Arial", size=12)
    pdf.cell(200, 10, txt=f"Penetration Test Report: {target}", ln=True, align="C")
    pdf.cell(200, 10, txt="Scan Results:", ln=True)
    pdf.multi_cell(0, 10, scan_results)
    pdf.cell(200, 10, txt="Identified Vulnerabilities:", ln=True)
    for vuln in vulnerabilities:
        pdf.cell(200, 10, txt=f"- {vuln}", ln=True)
    pdf.cell(200, 10, txt="AI Recommendations:", ln=True)
    pdf.multi_cell(0, 10, ai_suggestions)
    filepath = os.path.join(CONFIG["output_dir"], f"{target}_report.pdf")
    pdf.output(filepath)

def interactive_mode():
    target = questionary.text("Enter the domain or IP address of the target:").ask()
    scan_tools = questionary.checkbox("Select scanning tools to use:", choices=["nmap", "nikto", "whatweb", "sslyze", "dnsenum"]).ask()
    scan_results = "\n".join([execute_command([tool, target]) for tool in scan_tools])
    vulnerabilities = vulners_lookup("nmap", "7.93")
    ai_suggestions = ai_analysis(scan_results)
    client = metasploit_setup()
    if client:
        for vuln in vulnerabilities:
            metasploit_exploit(client, vuln, target)
    generate_report(target, scan_results, vulnerabilities, ai_suggestions)

def interactive_scanning():
    target_type = questionary.select(
        "What type of target are you scanning?",
        choices=["Website", "Server", "Network"],
    ).ask()

    if target_type == "Website":
        domain = questionary.text("Enter the website domain:").ask()
        workflow = enhanced_scanning_workflow(domain, None)
    elif target_type == "Server":
        domain = questionary.text("Enter the server IP or domain:").ask()
        workflow = {
            "dns": dnsrecon_scan(domain),
            "services": nmap_scan(domain),
        }
    elif target_type == "Network":
        network = questionary.text("Enter the network range (e.g., 192.168.1.0/24):").ask()
        workflow = {
            "network_scan": masscan_scan(network),
        }
    else:
        workflow = {}

    generate_detailed_scan_report(workflow)

def generate_detailed_scan_report(scan_data):
    pdf = FPDF()
    pdf.add_page()
    pdf.set_font("Arial", size=12)
    pdf.cell(200, 10, txt="Detailed Scanning Report", ln=True, align="C")

    for section, results in scan_data.items():
        pdf.cell(200, 10, txt=section.upper(), ln=True)
        if isinstance(results, list):
            for result in results:
                pdf.multi_cell(0, 10, result or "No results")
        else:
            pdf.multi_cell(0, 10, results or "No results")

    filepath = os.path.join(CONFIG["output_dir"], "scanning_report.pdf")
    pdf.output(filepath)
    console.print(f"[bold green]Report saved to {filepath}[/bold green]")

def main():
    banner()
    parser = argparse.ArgumentParser(description="QuantumStrike - Advanced Penetration Testing Tool")
    parser.add_argument("--interactive", action="store_true", help="Run in interactive mode")
    args = parser.parse_args()
    if args.interactive:
        interactive_mode()
    else:
        console.print("[red]Please use --interactive to start the tool.[/red]")

if __name__ == "__main__":
    main()
