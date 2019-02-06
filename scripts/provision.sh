#!/usr/bin/env bash

sudo systemctl stop consul
sleep 5
sudo systemctl status consul
#search consul
DCNAME=${DCNAME}
DOMAIN=${DOMAIN}

which unzip curl socat jq route dig vim sshpass || {
apt-get update -y
apt-get install unzip socat jq dnsutils net-tools vim curl sshpass -y 
}
var2=$(hostname)
# Install consul\
CONSUL_VER=${CONSUL_VER}
which consul || {
echo "Determining Consul version to install ..."

CHECKPOINT_URL="https://checkpoint-api.hashicorp.com/v1/check"
if [ -z "$CURRENT_VER" ]; then
    CURRENT_VER=$(curl -s "${CHECKPOINT_URL}"/consul | jq .current_version | tr -d '"')
fi


if  ! [ "$CONSUL_VER" == "$CURRENT_VER" ]; then
    echo "THERE IS NEWER VERSION OF CONSUL: ${CURRENT_VER}"
    echo "Install is going to proceed with the older version: ${CONSUL_VER}"
fi

if [ -f "/vagrant/pkg/consul_${CONSUL_VER}_linux_amd64.zip" ]; then
		echo "Found Consul in /vagrant/pkg"
else
    echo "Fetching Consul version ${CONSUL_VER} ..."
    mkdir -p /vagrant/pkg/
    curl -s https://releases.hashicorp.com/consul/${CONSUL_VER}/consul_${CONSUL_VER}_linux_amd64.zip -o /vagrant/pkg/consul_${CONSUL_VER}_linux_amd64.zip
    if [ $? -ne 0 ]; then
        echo "Download failed! Exiting."
        exit 1
    fi
fi

echo "Installing Consul version ${CONSUL_VER} ..."
pushd /tmp
unzip /vagrant/pkg/consul_${CONSUL_VER}_linux_amd64.zip 
sudo chmod +x consul
sudo mv consul /usr/local/bin/consul

}

mkdir -p /vagrant/logs
mkdir -p /etc/consul.d
mkdir -p /etc/tls
sshpass -p 'vagrant' scp -o StrictHostKeyChecking=no vagrant@10.10.66.11:"/etc/vault.d/vault.crt" /etc/tls/

# Unsealing vault

curl \
    --request PUT \
    --cacert /etc/tls/vault.crt \
    --data "{ \"key\": \"`cat /vagrant/keys.txt | grep \"Unseal Key 1:\" | cut -c15-`\"}" \
    https://10.10.66.11:8200/v1/sys/unseal

curl \
    --request PUT \
    --cacert /etc/tls/vault.crt \
    --data "{ \"key\": \"`cat /vagrant/keys.txt | grep \"Unseal Key 2:\" | cut -c15-`\"}" \
    https://10.10.66.11:8200/v1/sys/unseal

curl \
    --request PUT \
    --cacert /etc/tls/vault.crt \
    --data "{ \"key\": \"`cat /vagrant/keys.txt | grep \"Unseal Key 3:\" | cut -c15-`\"}" \
    https://10.10.66.11:8200/v1/sys/unseal

# Starting consul
killall consul

LOG_LEVEL=${LOG_LEVEL}
if [ -z "${LOG_LEVEL}" ]; then
    LOG_LEVEL="info"
fi

if [ -d /vagrant ]; then
  mkdir /vagrant/logs
  LOG="/vagrant/logs/${var2}.log"
else
  LOG="vault.log"
fi

IFACE=`route -n | awk '$1 ~ "10.10" {print $8}'`
CIDR=`ip addr show ${IFACE} | awk '$2 ~ "10.10" {print $2}'`
IP=${CIDR%%/24}

sudo useradd --system --home /etc/consul.d --shell /bin/false consul
sudo chown --recursive consul:consul /etc/consul.d
sudo chmod -R 755 /etc/consul.d/
sudo mkdir --parents /tmp/consul
sudo chown --recursive consul:consul /tmp/consul
mkdir -p /tmp/consul_logs/
sudo chown --recursive consul:consul /tmp/consul_logs/

cat << EOF > /etc/systemd/system/consul.service
[Unit]
Description="HashiCorp Consul - A service mesh solution"
Documentation=https://www.consul.io/
Requires=network-online.target
After=network-online.target

[Service]
User=consul
Group=consul
ExecStart=/usr/local/bin/consul agent -config-dir=/etc/consul.d/
ExecReload=/usr/local/bin/consul reload
KillMode=process
Restart=on-failure
LimitNOFILE=65536


[Install]
WantedBy=multi-user.target

EOF


if [[ "${var2}" == "consul-server1" ]]; then
    encr=`consul keygen`
    cat << EOF > /etc/consul.d/encrypt.json

    {
        "encrypt": "${encr}"
    }
EOF
fi


if [[ "${var2}" =~ "consul-server" ]]; then
    killall consul
    CERTS=`curl --cacert /etc/tls/vault.crt --header "X-Vault-Token: \`cat /vagrant/keys.txt | grep "Initial Root Token:" | cut -c21-\`"        --request POST        --data '{"common_name": "'server.${DCNAME}.${DOMAIN}'", "alt_names": "localhost", "ip_sans": "127.0.0.1", "ttl": "24h"}'       https://10.10.66.11:8200/v1/pki_int/issue/example-dot-com`
    if [ $? -ne 0 ];then
    $echo 'There is no certificates received'
    exit 1
    fi
    echo $CERTS | jq -r .data.issuing_ca > /etc/tls/consul-agent-ca.pem
    echo $CERTS | jq -r .data.certificate > /etc/tls/consul-agent.pem
    echo $CERTS | jq -r .data.private_key > /etc/tls/consul-agent-key.pem
    SERVER_COUNT=${SERVER_COUNT}
    echo $SERVER_COUNT

    cat << EOF > /etc/consul.d/tls.json

    {
        "server": true,
        "node_name": "${var2}",
        "bind_addr": "${IP}",
        "client_addr": "0.0.0.0",
        "bootstrap_expect": ${SERVER_COUNT},
        "retry_join": ["10.10.56.11", "10.10.56.12"],
        "log_level": "${LOG_LEVEL}",
        "data_dir": "/tmp/consul",
        "enable_script_checks": true,
        "verify_incoming_rpc": true,
        "verify_incoming_https": false,
        "verify_outgoing": true,
        "verify_server_hostname": true,
        "domain": "${DOMAIN}",
        "datacenter": "${DCNAME}",
        "ca_file": "/etc/tls/consul-agent-ca.pem",
        "cert_file": "/etc/tls/consul-agent.pem",
        "key_file": "/etc/tls/consul-agent-key.pem",
        "ports": {
            "http": -1,
            "https": 8501
        },
    
        "ui": true,
        "client_addr": "0.0.0.0",
        "disable_remote_exec": true
    }

EOF

    sudo sshpass -p 'vagrant' scp -o StrictHostKeyChecking=no vagrant@10.10.56.11:"/etc/consul.d/encrypt.json" /etc/consul.d/
    sleep 1
    sudo systemctl enable consul
    sudo systemctl start consul
    journalctl -f -u consul.service > /vagrant/logs/${var2}.log &
    sleep 5
    sudo systemctl status consul

else
    if [[ "${var2}" =~ "client" ]]; then
        killall consul
        CERTS=`curl --cacert /etc/tls/vault.crt --header "X-Vault-Token: \`cat /vagrant/keys.txt | grep "Initial Root Token:" | cut -c21-\`"        --request POST        --data '{"common_name": "'client.${DCNAME}.${DOMAIN}'", "alt_names": "localhost", "ip_sans": "127.0.0.1", "ttl": "24h"}'       https://10.10.66.11:8200/v1/pki_int/issue/example-dot-com`
        if [ $? -ne 0 ];then
        $echo 'There is no certificates received'
        exit 1
        fi
        echo $CERTS | jq -r .data.issuing_ca > /etc/tls/consul-agent-ca.pem
        echo $CERTS | jq -r .data.certificate > /etc/tls/consul-agent.pem
        echo $CERTS | jq -r .data.private_key > /etc/tls/consul-agent-key.pem

        cat << EOF > /etc/consul.d/tls.json

        {
            "node_name": "${var2}",
            "bind_addr": "${IP}",
            "client_addr": "0.0.0.0",
            "retry_join": ["10.10.56.11", "10.10.56.12"],
            "log_level": "${LOG_LEVEL}",
            "data_dir": "/tmp/consul",
            "enable_script_checks": true,
            "verify_incoming_rpc": true,
            "verify_incoming_https": false,
            "verify_outgoing": true,
            "verify_server_hostname": true,
            "domain": "${DOMAIN}",
            "datacenter": "${DCNAME}",
            "ca_file": "/etc/tls/consul-agent-ca.pem",
            "cert_file": "/etc/tls/consul-agent.pem",
            "key_file": "/etc/tls/consul-agent-key.pem",
            "ports": {
                "http": -1,
                "https": 8501
            },
        
            "ui": true,
            "client_addr": "0.0.0.0",
            "disable_remote_exec": true
        }

EOF



        sudo sshpass -p 'vagrant' scp -o StrictHostKeyChecking=no vagrant@10.10.56.11:"/etc/consul.d/encrypt.json" /etc/consul.d/
        sleep 1

        sudo systemctl enable consul
        sudo systemctl start consul
        journalctl -f -u consul.service > /vagrant/logs/${var2}.log &
        sleep 5
        sudo systemctl status consul
    fi
fi


sleep 5
consul members -ca-file=/etc/tls/consul-agent-ca.pem -client-cert=/etc/tls/consul-agent.pem -client-key=/etc/tls/consul-agent-key.pem -http-addr="https://127.0.0.1:8501"


curl --cacert /etc/tls/vault.crt --header "X-Vault-Token: `cat /vagrant/keys.txt | grep \"Initial Root Token:\" | cut -c21-`" --request PUT https://10.10.66.11:8200/v1/sys/seal
