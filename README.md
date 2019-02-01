# Sample repo showing example of how to create TLS and Gossip encrypted consul cluster taking certificates from Vault

### We have 3 node consul cluster and 1 Vault server. 


Before you start you may want to customise the `DCNAME` and `DOMAIN` values in `Vagrantfile`.

In `install_vault.sh` we are installing and configuring Vault to create root CA and intermediate CA to sign the certificates that are allowed to be requested according to the role set.
With `provisioning.sh` we are installing, configuring and starting Consul as certificates for every node are requested.

# How to use:
1. Fork and clone
2. `vagrant up`

### Things it is not recommendet to change:
- hostnames of servers in `Vagrantfile`: Consul servers need to have a template name of `consul-server`xxx . Clients servers need to have a template name of `client`xxx
- Environment variables passed to the scripts in `Vagrantfile`
- The IPs of the servers or they need to be in `10.10.` range
