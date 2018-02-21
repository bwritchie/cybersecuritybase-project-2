# Setup

Install of Linux Mint 18.3
- install VirtualBox 5.2
- install vagrant 2.0.2
- intall packer 1.13

# Install kali Linux

Separate VM

# Install Metasploitable 3

First `git clone https://github.com/rapid7/metasploitable3.git`

then

`packer build --only=virtualbox-iso windows_2008_r2.json`

then

`vagrant box add windows_2008_r2_virtualbox.box --name=metasploitable3`

finally

`vagrant up`

# Install Snort on windows
