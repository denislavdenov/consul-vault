VAULT = "1.0.2"
SERVER_COUNT = 3
CONSUL_VER = "1.4.2"
LOG_LEVEL = "debug" #The available log levels are "trace", "debug", "info", "warn", and "err". If empty - default is "info"
DCNAME = "sofia"
DOMAIN = "denislav"


Vagrant.configure("2") do |config|
  config.vm.synced_folder ".", "/vagrant", disabled: false
  config.vm.provider "virtualbox" do |v|
    v.memory = 512
    v.cpus = 2
  
  end
  
  config.vm.define "vault-server" do |vault|
    vault.vm.box = "denislavd/xenial64"
    vault.vm.hostname = "vault-server"
    vault.vm.provision :shell, path: "scripts/install_vault.sh", env: {"VAULT" => VAULT,"DCNAME" => DCNAME,"DOMAIN" => DOMAIN}
    vault.vm.network "private_network", ip: "10.10.66.11"
  end

  (1..SERVER_COUNT).each do |i|
    config.vm.define "consul-server#{i}" do |node|
      node.vm.box = "denislavd/xenial64"
      node.vm.hostname = "consul-server#{i}"
      node.vm.provision :shell, path: "scripts/provision.sh", env: {"SERVER_COUNT" => SERVER_COUNT, "CONSUL_VER" => CONSUL_VER, "LOG_LEVEL" => LOG_LEVEL,"DCNAME" => DCNAME,"DOMAIN" => DOMAIN}
      node.vm.network "private_network", ip: "10.10.56.1#{i}"
      node.vm.network "forwarded_port", guest: 8500, host: 8500 + i
    end
  end
end