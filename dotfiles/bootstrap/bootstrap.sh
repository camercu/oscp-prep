#!/bin/bash

# exit when any command fails
set -e

RED=$(tput setaf 1)
GREEN=$(tput setaf 2)
YELLOW=$(tput setaf 3)
BLUE=$(tput setaf 4)
CLEAR=$(tput sgr0)

function info {
    echo "${BLUE}[*] $@${CLEAR}"
}

function warn {
    echo "${YELLOW}[!] $@${CLEAR}"
}

function error {
    echo "${RED}[x] $@${CLEAR}"
}

function success {
    echo "${GREEN}[+] $@${CLEAR}"
}

info "Ensuring VMWare Tools are installed..."
sudo apt update && sudo apt install -y open-vm-tools fuse3

info "Regenerating Host SSH Keys..."
sudo rm -v /etc/ssh/ssh_host_*
sudo dpkg-reconfigure openssh-server
sudo systemctl restart ssh

info "Installing prerequisites for Ansible..."
sudo apt update && sudo apt install -y python3 python3-pip

info "Installing Ansible..."
sudo python3 -m pip install ansible argcomplete

info "Running Ansible script..."
sudo ansible-playbook -v -i localhost, --connection=local -e "ansible_python_interpreter=$(which python3)" hackbox-init.yml

success "Done!"