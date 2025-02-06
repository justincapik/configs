#!/usr/bin/env bash
set -e  # Exit on most errors by default

# Update package lists
sudo apt-get update

# install oh-my-zsh
if [ -d /home/vagrant/.oh-my-zsh ]; then
  echo "Oh My Zsh is already installed. Skipping installation."
else
  echo "Installing Oh My Zsh..."
  sudo -u vagrant -H sh -c "$(curl -fsSL https://raw.github.com/ohmyzsh/ohmyzsh/master/tools/install.sh)"
fi

# List of packages you want to install
PACKAGES=(
	nmap
	hashcat
	ffuf
	gobuster
	hydra
	zaproxy
	proxychains
	sqlmap
	radare2
	metasploit-framework
	python2.7
	python3
	spiderfoot
	theharvester
	rdesktop
	crackmapexec
	exiftool
	curl
	seclists
	testssl.sh
	vim
)

# Install each package individually so we can continue if one fails
for pkg in "${PACKAGES[@]}"; do
	echo "Attempting to install $pkg..."
	# Use '|| true' to avoid failing the entire script if one package fails
	sudo apt-get install -y "$pkg" || echo "WARNING: Failed to install $pkg. Continuing..."
done

sudo apt autoremove -y

#VS Code
sudo apt-get install -y wget gpg apt-transport-https software-properties-common
wget https://vscode.download.prss.microsoft.com/dbazure/download/stable/33fc5a94a3f99ebe7087e8fe79fbe1d37a251016/code_1.97.0-1738712383_arm64.deb -o /home/vagrant/Downloads/vscode.deb
sudo apt-get install -y /home/vagrant/Downloads/vscode.deb

