#!/usr/bin/env bash
VAULT=${VAULT}
DCNAME=${DCNAME}
DOMAIN=${DOMAIN}

echo $DCNAME
echo $DOMAIN

which unzip curl jq /sbin/route vim sshpass || {
apt-get update -y
apt-get install unzip jq net-tools vim curl sshpass -y 
}

set -x

mkdir -p /vagrant/pkg/
# insall vault

which vault || {
  pushd /vagrant/pkg
  [ -f vault_${VAULT}_linux_amd64.zip ] || {
    sudo wget https://releases.hashicorp.com/vault/${VAULT}/vault_${VAULT}_linux_amd64.zip
  }

  popd
  pushd /tmp

  sudo unzip /vagrant/pkg/vault_${VAULT}_linux_amd64.zip
  sudo chmod +x vault
  sudo mv vault /usr/local/bin/vault
  popd
}

# IFACE=`route -n | grep 10. | grep -v 10.0 | awk '{print $8}'`
# CIDR=`ip addr show ${IFACE} | grep inet | awk '{print $2}' | head -1`
# IP=${CIDR%%/24}
hostname=$(hostname)

if [ -d /vagrant ]; then
  mkdir /vagrant/logs
  LOG="/vagrant/logs/${hostname}.log"
else
  LOG="vault.log"
fi

#lets kill past instance
sudo killall vault &>/dev/null
sudo killall vault &>/dev/null
sudo killall vault &>/dev/null

# Copy vault configuration inside /etc/vault.d

[ -f /vagrant/etc/vault.d/config.hcl ] && sudo mkdir -p /etc/vault.d; sudo cp /vagrant/etc/vault.d/* /etc/vault.d/

############################################
cat << EOF > /usr/lib/ssl/req.conf

[req]
distinguished_name = req_distinguished_name
x509_extensions = v3_req
prompt = no
[req_distinguished_name]
C = BG
ST = sofia
L = sofia
O = denislav
OU = denislav
CN = sofia.denislav
[v3_req]
keyUsage = keyEncipherment, dataEncipherment
extendedKeyUsage = serverAuth
subjectAltName = @alt_names
[alt_names]
DNS.1 = localhost
IP.1 = 127.0.0.1
IP.2 = 10.10.66.11

EOF

pushd /etc/vault.d


openssl req -x509 -batch -nodes -newkey rsa:2048 -keyout vault.key -out vault.crt -config /usr/lib/ssl/req.conf -days 9999
cat vault.crt >> /usr/lib/ssl/certs/ca-certificates.crt

popd


############################################

# setup .bash_profile
grep VAULT_ADDR ~/.bash_profile || {
  echo export VAULT_ADDR=https://127.0.0.1:8200 | sudo tee -a ~/.bash_profile
}

#start vault
sudo /usr/local/bin/vault server -config=/etc/vault.d/config.hcl  &> ${LOG} &
echo vault started
sleep 3 


source ~/.bash_profile

vault operator init > /vagrant/keys.txt
vault operator unseal $(cat /vagrant/keys.txt | grep "Unseal Key 1:" | cut -c15-)
vault operator unseal $(cat /vagrant/keys.txt | grep "Unseal Key 2:" | cut -c15-)
vault operator unseal $(cat /vagrant/keys.txt | grep "Unseal Key 3:" | cut -c15-)
vault login $(cat /vagrant/keys.txt | grep "Initial Root Token:" | cut -c21-)


# enable secret KV version 1
sudo VAULT_ADDR="https://127.0.0.1:8200" vault secrets enable -version=1 kv
  


sudo VAULT_ADDR="https://127.0.0.1:8200" vault secrets enable pki
sudo VAULT_ADDR="https://127.0.0.1:8200" vault secrets tune -max-lease-ttl=87600h pki
sudo VAULT_ADDR="https://127.0.0.1:8200" vault write -field=certificate pki/root/generate/internal common_name="${DCNAME}.${DOMAIN}" alt_names="localhost" ip_sans="127.0.0.1" ttl=87600h > CA_cert.crt
sudo VAULT_ADDR="https://127.0.0.1:8200" vault write pki/config/urls issuing_certificates="https://127.0.0.1:8200/v1/pki/ca" crl_distribution_points="https://127.0.0.1:8200/v1/pki/crl"
sudo VAULT_ADDR="https://127.0.0.1:8200" vault secrets enable -path=pki_int pki
sudo VAULT_ADDR="https://127.0.0.1:8200" vault secrets tune -max-lease-ttl=43800h pki_int
sudo VAULT_ADDR="https://127.0.0.1:8200" vault write -format=json pki_int/intermediate/generate/internal common_name="${DCNAME}.${DOMAIN} Intermediate Authority" alt_names="localhost" ip_sans="127.0.0.1" ttl="43800h" | jq -r '.data.csr' > pki_intermediate.csr
sudo VAULT_ADDR="https://127.0.0.1:8200" vault write -format=json pki/root/sign-intermediate csr=@pki_intermediate.csr format=pem_bundle | jq -r '.data.certificate' > intermediate.cert.pem
sudo VAULT_ADDR="https://127.0.0.1:8200" vault write pki_int/intermediate/set-signed certificate=@intermediate.cert.pem
sudo VAULT_ADDR="https://127.0.0.1:8200" vault write pki_int/roles/example-dot-com allowed_domains="${DCNAME}.${DOMAIN}" alt_names="localhost" ip_sans="127.0.0.1" allow_subdomains=true max_ttl="720h"

set +x