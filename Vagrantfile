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

  config.vm.box = "hashicorp/bionic64"
  config.vm.provision "docker" do |d|
    d.build_image "/lazytun/Dockerfile", "-t \"lazytun\" "
    d.run "lazytun"
  end
  config.vm.hostname = "ipou"
  config.vm.disk :disk, size: "35GB", primary: true

  config.vm.provider "qemu" do |v|
    # Display the VirtualBox GUI when booting the machine
    v.gui = true
    v.name = "ipou"
    # Customize the amount of memory on the VM:
    v.memory = 4096
    v.cpus = 4
    v.automount = true
  end

  # copy source code
  # config.vm.provision "file", source: "./", destination: "~/remote/lazytun/"
  #
  # View the documentation for the provider you are using for more
  # information on available options.

  # Enable provisioning with a shell script. Additional provisioners such as
  # Ansible, Chef, Docker, Puppet and Salt are also available. Please see the
  # documentation for more information about their specific syntax and use.
  config.vm.provision "shell", inline: <<-SHELL
    apt-get update
    apt-get install -y curl
    curl --proto '=https' --tlsv1.2 -sSf https://sh.rustup.rs | sh
  SHELL
end
