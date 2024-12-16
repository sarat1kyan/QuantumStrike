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
import logging

console = Console()
logging.basicConfig(level=logging.INFO, format='%(asctime)s - %(levelname)s - %(message)s')

CONFIG = {
    "api_keys": {
        "vulners": os.getenv("VULNERS_API_KEY", "your_vulners_api_key"),
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
        "[bold yellow]Version 4.0 - QuantumStrike CLI[/bold yellow]"
    )

def execute_command(command):
    try:
        result = subprocess.run(command, capture_output=True, text=True, check=True)
        return result.stdout
    except subprocess.CalledProcessError as e:
        logging.error(f"Command '{' '.join(command)}' failed: {e.stderr}")
        return None

def parse_tool_output(output, pattern):
    parsed = []
    lines = output.split("\n")
    for line in lines:
        match = re.search(pattern, line)
        if match:
            parsed.append(match.groupdict())
    return parsed

def interactive_mode():
    target = questionary.txt("Enter the domain or IP address of the target:").ask()
    scan_tools = questionary.checkbox(
        "Select scanning tools to use:", choices=["nmap", "masscan", "nikto", "amass"]
    ).ask()
    
    scan_results = {}
    for tool in scan_tools:
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
    
    summary = summarize_scan_results(scan_results)
    console.print(summary)
    generate_report(target, scan_results)

def summarize_scan_results(scan_data):
    summary = []
    for tool, results in scan_data.items():
        summary.append(f"[bold yellow]{tool.upper()} Results:[/bold yellow]")
        if isinstance(results, list):
            for res in results:
                summary.append(f"- {res}")
        elif isinstance(results, dict):
            for res in results.values():
                summary.append(f"- {res}")
        else:
            summary.append(results)
    return "\n".join(summary)

def generate_report(target, scan_data):
    pdf = FPDF()
    pdf.add_page()
    pdf.set_font("Arial", size=12)
    pdf.cell(200, 10, text=f"Penetration Testing Report: {target}", ln=True, align="C")
    for tool, results in scan_data.items():
        pdf.cell(200, 10, text=f"{tool.upper()} Results:", ln=True)
        if isinstance(results, list):
            for result in results:
                pdf.multi_cell(0, 10, str(result))
        else:
            pdf.multi_cell(0, 10, str(results))
    filepath = os.path.join(CONFIG["output_dir"], f"{target}_report.pdf")
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
