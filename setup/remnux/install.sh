#!/usr/bin/env bash
set -e  # Exit on most errors by default

# Set Paris time
echo "Europe/Paris" > /etc/timezone
ln -sf /usr/share/zoneinfo/Europe/Paris /etc/localtime
dpkg-reconfigure -f noninteractive tzdata

# Update package lists
echo "INSTALLING UPDATES"
echo "INSTALLING autoremove"
sudo apt autoremove -y
echo "INSTALLING update"
sudo apt-get update -y
echo "INSTALLING autoremove"
sudo apt autoremove -y
echo "FINISHED INSTALLING UPDATES"


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
	jq
	freerdp3-x11
	ncat
	htop
	webp
	apt-transport-https
	gnupg
	lsb-release
	sudo apt update
)

sudo apt update -y

# Install each package individually so we can continue if one fails
for pkg in "${PACKAGES[@]}"; do
	echo "Attempting to install $pkg..."
	# Use '|| true' to avoid failing the entire script if one package fails
	sudo apt-get install -y "$pkg" || \
		echo "WARNING: Failed to install $pkg. Continuing..."
done


sudo apt autoremove -y

#VS Code

# Import Microsoft GPG key and add the repository
curl -sSL https://packages.microsoft.com/keys/microsoft.asc | gpg --dearmor | sudo tee /usr/share/keyrings/packages.microsoft.gpg > /dev/null
echo "deb [arch=amd64 signed-by=/usr/share/keyrings/packages.microsoft.gpg] https://packages.microsoft.com/repos/code stable main" | sudo tee /etc/apt/sources.list.d/vscode.list

# Update and install VSCode
sudo apt-get update -y
sudo apt-get install -y code

# Install vscode extensions
sudo -u vagrant -H code --install-extension vscodevim.vim
sudo -u vagrant -H code --install-extension yzhang.markdown-all-in-one
sudo -u vagrant -H code --install-extension tomoki1207.pdf
