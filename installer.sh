#!/bin/bash

install_python_dependencies() {
  echo "Checking and installing Python dependencies..."
  if command -v python3 &>/dev/null; then
    PYTHON=python3
  elif command -v python &>/dev/null; then
    PYTHON=python
  else
    echo "Python is not installed. Please install Python manually."
    exit 1
  fi

  if ! command -v pip &>/dev/null; then
    echo "pip is not installed. Installing pip..."
    $PYTHON -m ensurepip --upgrade
    $PYTHON -m pip install --upgrade pip
  fi

  if [ ! -f "requirements.txt" ]; then
    echo "requirements.txt not found! Please ensure it exists in the current directory."
    exit 1
  fi

  pip install -r requirements.txt
}

install_system_tools() {
  echo "Checking and installing required system tools..."
  tools=(nmap nikto whatweb sslyze dnsenum masscan amass httprobe nuclei subfinder)

  for tool in "${tools[@]}"; do
    if ! command -v "$tool" &>/dev/null; then
      echo "$tool is not installed. Installing $tool..."
      if command -v apt &>/dev/null; then
        sudo apt update && sudo apt install -y "$tool"
      elif command -v yum &>/dev/null; then
        sudo yum install -y "$tool"
      else
        echo "Package manager not supported. Please install $tool manually."
      fi
    else
      echo "$tool is already installed."
    fi
  done
}

install_go() {
  if ! command -v go &>/dev/null; then
    echo "Go is not installed. Installing Go..."
    if command -v apt &>/dev/null; then
      sudo apt update && sudo apt install -y golang
    elif command -v yum &>/dev/null; then
      sudo yum install -y golang
    else
      echo "Package manager not supported. Please install Go manually."
      return
    fi
  else
    echo "Go is already installed."
  fi
}

install_httprobe() {
  if ! command -v httprobe &>/dev/null; then
    echo "httprobe is not installed. Installing httprobe..."
    if command -v go &>/dev/null; then
      go install github.com/tomnomnom/httprobe@latest
      sudo mv "$(go env GOPATH)/bin/httprobe" /usr/local/bin/
    else
      echo "Go is not installed. Please install Go to proceed with httprobe installation."
    fi
  else
    echo "httprobe is already installed."
  fi
}

install_metasploit() {
  echo "Checking and installing Metasploit..."
  if ! command -v msfconsole &>/dev/null; then
    echo "Metasploit is not installed. Installing Metasploit..."
    if command -v apt &>/dev/null; then
      curl https://raw.githubusercontent.com/rapid7/metasploit-framework/master/msfinstall > msfinstall
      chmod +x msfinstall
      sudo ./msfinstall
      rm msfinstall
    else
      echo "Please install Metasploit manually. Visit: https://docs.metasploit.com/docs/using-metasploit/getting-started.html"
    fi
  else
    echo "Metasploit is already installed."
  fi
}

main() {
  echo "Starting QuantumStrike installation process..."
  install_python_dependencies
  install_system_tools
  install_go
  install_httprobe
  install_metasploit
  echo "All dependencies are installed and ready!"
}

main
