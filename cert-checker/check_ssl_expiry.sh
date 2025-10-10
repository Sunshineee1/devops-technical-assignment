#!/bin/bash

# Variables
CONFIG_FILE="domains.conf"
WARNING_DAYS=30     
CRITICAL_DAYS=7    
SSL_PORT=443

#MAil settings

Recipient="elizabeth.krasimirova@gmail.com"
Sender="ssl-checker@sunshine.com"
Subject="CRITICAL ALERT: SSL Certificate Expiry Check"

# Functions for alerts
log_alert() {
    local SEVERITY=$1
    local DOMAIN=$2
    local MESSAGE=$3
    
# ANSI 
    RED='\033[0;31m'
    YELLOW='\033[0;33m'
    GREEN='\033[0;32m'
    NC='\033[0m' # No Color
    local COLOR=$NC
    
    case "$SEVERITY" in
        "CRITICAL") COLOR=$RED ;;
        "WARNING") COLOR=$YELLOW ;;
        "OK") COLOR=$GREEN ;;
        "ERROR") COLOR=$RED ;;
    esac
# Results
    echo -e "${COLOR}[$SEVERITY]${NC} - ${DOMAIN}: $MESSAGE"
}

# Sending email



check_ssl_expiry() {
    local DOMAIN=$1
    echo "--- Cheking on $DOMAIN ---"
    
#  Taking data and date of expiry   
    EXPIRY_DATE_RAW=$(echo -n | openssl s_client -servername "$DOMAIN" -connect "$DOMAIN":"$SSL_PORT" 2>/dev/null | openssl x509 -noout -enddate 2>/dev/null | awk -F= '{print $2}')
#  Errors 
    if [ -z "$EXPIRY_DATE_RAW" ]; then
        log_alert "ERROR" "$DOMAIN" "Unable to retrieve certificate information. Domain is unavailable or does not support SSL."
        echo "--------------------------"
        return 1
    fi
# Format the date
    EXPIRY_SEC=$(date -d "$EXPIRY_DATE_RAW" +%s 2>/dev/null)
    if [ $? -ne 0 ]; then
        log_alert "ERROR" "$DOMAIN" "Date parsing failed: $EXPIRY_DATE_RAW"
        echo "--------------------------"
        return 1
    fi
    TODAY_SEC=$(date +%s)
    
    SECONDS_LEFT=$((EXPIRY_SEC - TODAY_SEC))
    DAYS_LEFT=$(echo "($SECONDS_LEFT / 86400)" | bc)

    EXPIRY_DATE_HUMAN=$(date -d "$EXPIRY_DATE_RAW" +'%Y-%m-%d %H:%M:%S %Z')
    
# 4 Results
    
    #Check for expired certificate (Days Left < 0)
    if [ "$DAYS_LEFT" -lt 0 ]; then
        log_alert "CRITICAL" "$DOMAIN" "CERTIFICATE EXPIRED before $DAYS_LEFT days! (Expired on: $EXPIRY_DATE_HUMAN)"
    # Check for CRITICAL  (<7)
    elif [ "$DAYS_LEFT" -le "$CRITICAL_DAYS" ]; then
        log_alert "CRITICAL" "$DOMAIN" "The certificate expires after $DAYS_LEFT days! (Expiration date: $EXPIRY_DATE_HUMAN)"
    # Check for WARNING (<30)
    elif [ "$DAYS_LEFT" -le "$WARNING_DAYS" ]; then
        log_alert "WARNING" "$DOMAIN" "The certificate expires after$DAYS_LEFT days. (Expiration date: $EXPIRY_DATE_HUMAN)"
    else
        log_alert "OK" "$DOMAIN" "The certificate is still valid $DAYS_LEFT days. (Expiration date: $EXPIRY_DATE_HUMAN)"
    fi
    
    echo "--------------------------"
}
echo "==================================================="
echo "     SSL/TLS Checker (Bash Script)      "
echo "==================================================="

# Check for config file 
if [ ! -f "$CONFIG_FILE" ]; then
    log_alert "ERROR" "$CONFIG_FILE" "The configuration file is not found!"
    exit 1
fi

while IFS= read -r DOMAIN || [[ -n "$DOMAIN" ]]; do
    if [[ "$DOMAIN" =~ ^#.* ]] || [[ -z "$DOMAIN" ]]; then
        continue
    fi
    check_ssl_expiry "$DOMAIN"

done < "$CONFIG_FILE"

echo "Verification completed."
