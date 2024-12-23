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

def interactive_mode():
    target = questionary.text("Enter the domain or IP address of the target:").ask()
    if not validate_target(target):
        return

    scan_tools = questionary.checkbox(
        "Select scanning tools to use:", choices=["nmap", "masscan", "nikto", "amass"]
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
    pdf.set_font("Helvetica", size=12)
    
    pdf.cell(0, 10, text=f"Penetration Testing Report: {target}", new_x="LMARGIN", new_y="NEXT", align="C")
    
    for tool, results in scan_data.items():
        pdf.set_font("Helvetica", size=12, style="B")
        pdf.cell(0, 10, text=f"{tool.upper()} Results:", new_x="LMARGIN", new_y="NEXT")
        pdf.set_font("Helvetica", size=12)
        
        if isinstance(results, list):
            for result in results:
                wrapped_text = pdf.multi_cell(0, 10, str(result), new_x="LMARGIN", new_y="NEXT")
        elif isinstance(results, dict):
            for key, value in results.items():
                pdf.multi_cell(0, 10, f"{key}: {value}", new_x="LMARGIN", new_y="NEXT")
        else:
            pdf.multi_cell(0, 10, str(results), new_x="LMARGIN", new_y="NEXT")
    
    filepath = os.path.join(CONFIG["output_dir"], f"{target}_report.pdf")
    try:
        pdf.output(filepath)
        console.print(f"[bold green]Report saved to {filepath}[/bold green]")
    except Exception as e:
        console.print(f"[bold red]Failed to save report: {str(e)}[/bold red]")

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
