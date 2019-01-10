# -*- mode: ruby -*-
# vi: set ft=ruby :

# All Vagrant configuration is done below. The "2" in Vagrant.configure
# configures the configuration version (we support older styles for
# backwards compatibility). Please don't change it unless you know what
# you're doing.
Vagrant.configure("2") do |config|
  # The most common configuration options are documented and commented below.
  # For a complete reference, please see the online documentation at
  # https://docs.vagrantup.com.

  # Every Vagrant development environment requires a box. You can search for
  # boxes at https://vagrantcloud.com/search.
  config.vm.box = "ubuntu/xenial64"

  config.vm.network "forwarded_port", host_ip: "127.0.0.1", guest: 3000, host: 8070
  # REF: https://www.vagrantup.com/docs/networking/public_network.html
  config.vm.network "public_network", :bridge=> "Intel(R) Centrino(R) Wireless-N 2200", ip: "192.168.1.37"

  config.vm.provision "shell", inline: <<-SHELL
    # Update and upgrade the server packages.
    sudo apt-get update
    sudo apt-get -y upgrade
    # Set Ubuntu Language
    sudo locale-gen en_GB.UTF-8
    # Install most recent version of nodejs via PPA
    # 1. Add Nodejs PPA
    sudo apt-get -y install python-software-properties
    curl -sL https://deb.nodesource.com/setup_8.x | sudo -E bash -
    # 2. Install Nodejs and NPM
    sudo apt-get -y install nodejs
    # 3. Downgrading NPM to a previous stable bug free version
    sudo npm install -g npm@5.6.0
    # 4. Install Express Generator and Nodemon using npm
    sudo npm install -g express-generator nodemon
    # 5. Install redis server:
    sudo apt-get -y install redis-server
  SHELL
end
