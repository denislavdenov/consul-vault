# Sample repo showing example of how to create TLS and Gossip encrypted consul cluster taking certificates from Vault

### We have 3 node consul cluster and 1 Vault server. 


Before you start you may want to customise the `DCNAME` and `DOMAIN` values in `Vagrantfile`.

In `install_vault.sh` we are installing and configuring Vault to create root CA. We define a common name. This is how Vault expects servers' name to be who contact it for certificates.
We create an intermediate CA and create a chain of trust in order to keep our root CA safe.
With the intermediate CA we are signing the certificates that are allowed to be requested according to the role set.
The role that we have set allows for servers from the allowed domain that can also be a subdomains of the one configured in the root and intermediate CA common name.
When a request from server in the allowed domain is created, it is provided with signed certificate that includes a common name set as per the expectations of Consul. In this example the common name for Consul servers is `servers.sofia.denislav`.
Any server or a client that is in the subdomain `sofia.denislav` can request and receive an signed certificate from the intermediate CA. Certificates also incliude in themselves and Subject Alternative Name `localhost` and IP_SAN `127.0.0.1`
In this example this is needed in order to make consul CLI commands to work. If we do not configure that we are going to get error that certificate provided is only signe for `server.sofia.denislav` and we cannot use it for an unknown host `localhost` or `127.0.0.1`.
In general, every consul server is treated like `server.sofia.denislav`, but we cannot use that for Consul CLI commands to work since this FQDN is not resolveable by our DNS.
Another way of resolving this issue is installing and configuring DNSMASQ to resolve Consul FQDNs.
Then we have to specify that we also need another SAN - `${hostname}.sofia.node.denislav`

With `provisioning.sh` we are installing, configuring and starting Consul as certificates for every node are requested.

# How to use:
1. Fork and clone
2. `vagrant up`

### Things it is not recommended to change:
- hostnames of servers in `Vagrantfile`: Consul servers need to have a template name of `consul-server`xxx . Clients servers need to have a template name of `client`xxx
- Environment variables passed to the scripts in `Vagrantfile`
- The IPs of the servers or they need to be in `10.10.` range
