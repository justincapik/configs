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
	jq
	freerdp2-x11
	ncat
)

# Install each package individually so we can continue if one fails
for pkg in "${PACKAGES[@]}"; do
	echo "Attempting to install $pkg..."
	# Use '|| true' to avoid failing the entire script if one package fails
	sudo apt-get install -y "$pkg" || echo "WARNING: Failed to install $pkg. Continuing..."
done

sudo apt autoremove -y



#VS Code

# Import Microsoft GPG key and add the repository
curl -sSL https://packages.microsoft.com/keys/microsoft.asc | gpg --dearmor | sudo tee /usr/share/keyrings/packages.microsoft.gpg > /dev/null
echo "deb [arch=amd64 signed-by=/usr/share/keyrings/packages.microsoft.gpg] https://packages.microsoft.com/repos/code stable main" | sudo tee /etc/apt/sources.list.d/vscode.list

# Update and install VSCode
sudo apt-get update
sudo apt-get install -y code

# Install vscode extensions
sudo -u vagrant -H code --install-extension vscodevim.vim
sudo -u vagrant -H code --install-extension yzhang.markdown-all-in-one
sudo -u vagrant -H code --install-extension tomoki1207.pdf
