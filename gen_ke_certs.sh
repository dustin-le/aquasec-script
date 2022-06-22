#!/bin/bash
# Simple shell script to generate required SSL certificates to be used with Aqua KubeEnforcer
# Assumes yes for all user input for scripting purposes and hardcode password

_banner() {
    echo
    echo "In this script you will configure and deploy Aqua KubeEnforcer config to your kubernetes cluster"
    echo
    echo "This script will: "
    echo " * Generate SSL certs signed by private root CA bundle"
    echo " * Download and prepare Aqua KubeEnforcer admission controller manifest"
    echo " * Deploy Aqua KubeEnforcer admission controller (if needed)"
    echo
    echo
    _generate_ca
}

_check_k8s_connection() {
    if ! command -v kubectl &> /dev/null
    then
        echo "kubectl command could not be found"
        exit 1
    fi

    if ! `$(command -v kubectl) version &> /dev/null`; then
        echo "Dont have access to kubernetes cluster"
        exit 1
    fi
}

_generate_ca() {
    printf "\nInfo: Generating root CA private key\n"
    if `openssl genrsa -des3 -out rootCA.key -passout pass:ticketing 4096`; then
        printf "\nInfo: Successfully generated rootCA.key\n"
        printf "Info: Generating root CA certificate from root CA private key with admission_ca as common name\n"
        if `openssl req -x509 -new -nodes -key rootCA.key -passin pass:ticketing -sha256 -days 1024 -out rootCA.crt -subj "//CN=admission_ca"`; then
            printf "\nInfo: Successfully generated rootCA.crt\n"
            _generate_ssl
        else
            printf "\nError: Failed to generate root CA certificate"
            exit 1
        fi
    else
        printf "\nError: Failed to generate root CA private key"
        exit 1
    fi
}

_generate_ssl() {
    printf "\nInfo: Generating kubeEnforcer SSL private key\n"
    if `openssl genrsa -out aqua_ke.key 2048`; then
        printf "\nInfo: Successfully generated aqua_ke.key\n"
        # CSR config file to generate kubeEnforcer CSR
        cat > server.conf <<-EOF
        [req]
        req_extensions = v3_req
        distinguished_name = req_distinguished_name
        [req_distinguished_name]
        [ alt_names ]
        DNS.1 = aqua-kube-enforcer.aqua.svc
        DNS.2 = aqua-kube-enforcer.aqua.svc.cluster.local
        [ v3_req ]
        basicConstraints = CA:FALSE
        keyUsage = nonRepudiation, digitalSignature, keyEncipherment
        extendedKeyUsage = clientAuth, serverAuth
        subjectAltName = @alt_names
EOF
        printf "\nInfo: Generating kubeEnforcer CSR\n"
        if `openssl req -new -sha256 -key aqua_ke.key -subj "//CN=aqua-kube-enforcer.aqua.svc" -config server.conf -out aqua_ke.csr`; then
            printf "\nInfo: Successfully generated aqua_ke.csr\n"
            printf "\nInfo: Generating kubeEnforcer certificate\n"
            if `openssl x509 -req -in aqua_ke.csr -CA rootCA.crt -CAkey rootCA.key -passin pass:ticketing -CAcreateserial -out aqua_ke.crt -days 365 -sha256 -extensions v3_req -extfile server.conf`; then
                printf "\nInfo: Successfully generated aqua_ke.crt\n"
                _prepare_ke
            else
                printf "\nError: Failed to generate KubeEnforcer certificate"
                exit 1
            fi
        else
            printf "\nError: Failed to generate kubeEnforcer CSR"
            exit 1
        fi

    else
        printf "\nError: Failed to generate kubeEnforcer SSL private key"
        exit 1
    fi
}

_prepare_ke() {
    if `curl https://raw.githubusercontent.com/aquasecurity/deployments/5.3/orchestrators/kubernetes/manifests/aqua_csp_009_enforcer/kube_enforcer/001_kube_enforcer_config.yaml -o "001_kube_enforcer_config.yaml"`; then
        _rootCA=`cat rootCA.crt | base64 | tr -d '\n' | tr -d '\r'`
        if `sed -i'.original' "s/caBundle:/caBundle\:\ $_rootCA/g" 001_kube_enforcer_config.yaml`; then
            printf "\nInfo: Successfully prepared 001_kube_enforcer_config.yaml manifest file.\n"
            _deploy_ke_admin
        else
            printf "\nError: Failed to prepare KubeEnforcer config file"
            exit 1
        fi
    else
        printf "\nError: Failed to download 001_kube_enforcer_config.yaml manifest file"
    fi
}

_deploy_ke_admin() {
    _check_k8s_connection
    echo
    if `$(command -v kubectl) apply -f 001_kube_enforcer_config.yaml &> /dev/tty`; then
        printf "\nInfo: KubeEnforcer config successfully deployed\n"
        printf "Info: Please proceed with secrets and pod deployment\n"
    else
        printf "Error: Failed to apply KubeEnforcer config to the cluster\n"
    fi
}

_banner