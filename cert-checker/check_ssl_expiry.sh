#!/bin/bash

# Конфигурационни Променливи
CONFIG_FILE="domains.conf"
WARNING_DAYS=30     
CRITICAL_DAYS=7    
SSL_PORT=443

# Функция за обработка на грешки и извеждане на аларми
log_alert() {
    local SEVERITY=$1
    local DOMAIN=$2
    local MESSAGE=$3
    
# ANSI цветове
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
    
# Отпечатва алармата
    echo -e "${COLOR}[$SEVERITY]${NC} - ${DOMAIN}: $MESSAGE"
}

# Функция за извличане и проверка на сертификата
check_ssl_expiry() {
    local DOMAIN=$1
    echo "--- Проверка на $DOMAIN ---"
    
    # 1. Извличане на сертификатната информация и датата на изтичане    
    EXPIRY_DATE_RAW=$(echo -n | openssl s_client -servername "$DOMAIN" -connect "$DOMAIN":"$SSL_PORT" 2>/dev/null | openssl x509 -noout -enddate 2>/dev/null | awk -F= '{print $2}')

# 2. Обработка на грешки 
    if [ -z "$EXPIRY_DATE_RAW" ]; then
        log_alert "ERROR" "$DOMAIN" "Не може да се извлече сертификатната информация. Домейнът е недостъпен или не поддържа SSL."
        echo "--------------------------"
        return 1
    fi
    
# 3. Взимане и форматиране на датата
    EXPIRY_SEC=$(date -d "$EXPIRY_DATE_RAW" +%s 2>/dev/null)
    if [ $? -ne 0 ]; then
        log_alert "ERROR" "$DOMAIN" "Неуспешно парсване на датата: $EXPIRY_DATE_RAW"
        echo "--------------------------"
        return 1
    fi
    TODAY_SEC=$(date +%s)
    
# Изчисляване на разликата в дни
    SECONDS_LEFT=$((EXPIRY_SEC - TODAY_SEC))
    DAYS_LEFT=$(echo "($SECONDS_LEFT / 86400)" | bc)

    EXPIRY_DATE_HUMAN=$(date -d "$EXPIRY_DATE_RAW" +'%Y-%m-%d %H:%M:%S %Z')
    
# 4. Резултати
    
    # Проверка за изтекъл сертификат (Days Left < 0)
    if [ "$DAYS_LEFT" -lt 0 ]; then
        log_alert "CRITICAL" "$DOMAIN" "СЕРТИФИКАТЪТ Е ИЗТЕКЪЛ преди $DAYS_LEFT дни! (Изтекъл на: $EXPIRY_DATE_HUMAN)"
    # Проверка за CRITICAL праг (< 7 дни)
    elif [ "$DAYS_LEFT" -le "$CRITICAL_DAYS" ]; then
        log_alert "CRITICAL" "$DOMAIN" "Сертификатът изтича след $DAYS_LEFT дни! (Дата на изтичане: $EXPIRY_DATE_HUMAN)"
    # Проверка за WARNING праг (< 30 дни)
    elif [ "$DAYS_LEFT" -le "$WARNING_DAYS" ]; then
        log_alert "WARNING" "$DOMAIN" "Сертификатът изтича след $DAYS_LEFT дни. (Дата на изтичане: $EXPIRY_DATE_HUMAN)"
    else
        log_alert "OK" "$DOMAIN" "Сертификатът е валиден още $DAYS_LEFT дни. (Дата на изтичане: $EXPIRY_DATE_HUMAN)"
    fi
    
    echo "--------------------------"
}
echo "==================================================="
echo "     SSL/TLS Сертификат Checker (Bash Script)      "
echo "==================================================="

# Проверка дали конфиг файла съществува
if [ ! -f "$CONFIG_FILE" ]; then
    log_alert "ERROR" "$CONFIG_FILE" "Конфигурационният файл не е намерен!"
    exit 1
fi

# Четене на домейните ред по ред
while IFS= read -r DOMAIN || [[ -n "$DOMAIN" ]]; do
    if [[ "$DOMAIN" =~ ^#.* ]] || [[ -z "$DOMAIN" ]]; then
        continue
    fi
    check_ssl_expiry "$DOMAIN"

done < "$CONFIG_FILE"

echo "Проверката приключи."
