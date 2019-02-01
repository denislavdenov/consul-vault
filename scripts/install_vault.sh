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

#delete old token if present
[ -f /root/.vault-token ] && sudo rm /root/.vault-token

# Copy vault configuration inside /etc/vault.d

[ -f /vagrant/etc/vault.d/vault.hcl ] && sudo mkdir -p /etc/vault.d; sudo cp /vagrant/etc/vault.d/vault.hcl /etc/vault.d/vault.hcl

#start vault
sudo /usr/local/bin/vault server  -dev -dev-listen-address=0.0.0.0:8200 -config=/etc/vault.d/  &> ${LOG} &
echo vault started
sleep 3 

grep VAULT_ADDR ~/.bash_profile || {
  echo export VAULT_ADDR=http://127.0.0.1:8200 | sudo tee -a ~/.bash_profile
}

echo "vault token:"
cat /root/.vault-token
echo -e "\nvault token is on /root/.vault-token"
  
# enable secret KV version 1
sudo VAULT_ADDR="http://127.0.0.1:8200" vault secrets enable -version=1 kv
  
# setup .bash_profile
grep VAULT_TOKEN ~/.bash_profile || {
  echo export VAULT_TOKEN=\`cat /root/.vault-token\` | sudo tee -a ~/.bash_profile
}

sudo find / -name '.vault-token' -exec cp {} /vagrant/.vault-token \; -quit
sudo chmod ugo+r /vagrant/.vault-token

sudo VAULT_ADDR="http://127.0.0.1:8200" vault secrets enable pki
sudo VAULT_ADDR="http://127.0.0.1:8200" vault secrets tune -max-lease-ttl=87600h pki
sudo VAULT_ADDR="http://127.0.0.1:8200" vault write -field=certificate pki/root/generate/internal common_name="${DCNAME}.${DOMAIN}" alt_names="localhost" ip_sans="127.0.0.1" ttl=87600h > CA_cert.crt
sudo VAULT_ADDR="http://127.0.0.1:8200" vault write pki/config/urls issuing_certificates="http://127.0.0.1:8200/v1/pki/ca" crl_distribution_points="http://127.0.0.1:8200/v1/pki/crl"
sudo VAULT_ADDR="http://127.0.0.1:8200" vault secrets enable -path=pki_int pki
sudo VAULT_ADDR="http://127.0.0.1:8200" vault secrets tune -max-lease-ttl=43800h pki_int
sudo VAULT_ADDR="http://127.0.0.1:8200" vault write -format=json pki_int/intermediate/generate/internal common_name="${DCNAME}.${DOMAIN} Intermediate Authority" alt_names="localhost" ip_sans="127.0.0.1" ttl="43800h" | jq -r '.data.csr' > pki_intermediate.csr
sudo VAULT_ADDR="http://127.0.0.1:8200" vault write -format=json pki/root/sign-intermediate csr=@pki_intermediate.csr format=pem_bundle | jq -r '.data.certificate' > intermediate.cert.pem
sudo VAULT_ADDR="http://127.0.0.1:8200" vault write pki_int/intermediate/set-signed certificate=@intermediate.cert.pem
sudo VAULT_ADDR="http://127.0.0.1:8200" vault write pki_int/roles/example-dot-com allowed_domains="${DCNAME}.${DOMAIN}" alt_names="localhost" ip_sans="127.0.0.1" allow_subdomains=true max_ttl="720h"