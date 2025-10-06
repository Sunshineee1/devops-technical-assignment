#!/bin/bash

################################################################################
# Скрипт за Проверка на Изтичане на SSL/TLS Сертификати
#
# Автор: Елизабет Иванова
# Дата:06.10.2025
#
# Описание:
# Чета списък с домейни от файл и проверява датата на изтичане на техните
# SSL/TLS сертификати, като изчислява оставащите дни.
# Имплементира прагове за WARNING и CRITICAL аларми.
#
# Изисквания:
# - openssl, date (с поддръжка на '-d'), grep, awk, bc
# - domains.conf (конфигурационен файл със списък с домейни)
################################################################################

# --- Конфигурационни Променливи ---
CONFIG_FILE="domains.conf"
WARNING_DAYS=30     # Предупреждение, ако остават по-малко от Х дни
CRITICAL_DAYS=7     # Грешка, ако остават по-малко от Х дни
SSL_PORT=443

# --- Функции ---

# Функция за обработка на грешки и извеждане на аларми (Advanced Optional)
log_alert() {
    local SEVERITY=$1
    local DOMAIN=$2
    local MESSAGE=$3
    
    # ANSI цветове за по-добър изход
    RED='\033[0;31m'
    YELLOW='\033[0;33m'
    GREEN='\033[0;32m'
    NC='\033[0m' # No Color
    
    local COLOR=$NC
    
    case "$SEVERITY" in
        "CRITICAL")
            COLOR=$RED
            ;;
        "WARNING")
            COLOR=$YELLOW
            ;;
        "OK")
            COLOR=$GREEN
            ;;
        "ERROR")
            COLOR=$RED
            ;;
    esac
    
    # Отпечатва алармата в унифициран формат
    echo -e "${COLOR}[$SEVERITY]${NC} - ${DOMAIN}: $MESSAGE"
}

# Функция за извличане и проверка на сертификата
check_ssl_expiry() {
    local DOMAIN=$1
    echo "--- Проверка на $DOMAIN ---"
    
    # 1. Извличане на сертификатната информация и датата на изтичане
    # Използваме OpenSSL s_client за установяване на SSL връзка и извличане на сертификата.
    # -servername: за SNI (Server Name Indication)
    # -connect: установява връзка с домейна на порт 443
    # 2>/dev/null: скрива OpenSSL предупрежденията/грешките за stderr (Network Issues Handling)
    # | openssl x509 -noout -enddate: филтрира за Not After (дата на изтичане)
    
    EXPIRY_DATE_RAW=$(echo -n | openssl s_client -servername "$DOMAIN" -connect "$DOMAIN":"$SSL_PORT" 2>/dev/null | openssl x509 -noout -enddate 2>/dev/null | awk -F= '{print $2}')

    # 2. Обработка на грешки при извличане (e.g., домейнът не съществува или е недостъпен)
    if [ -z "$EXPIRY_DATE_RAW" ]; then
        log_alert "ERROR" "$DOMAIN" "Не може да се извлече сертификатната информация. Домейнът е недостъпен или не поддържа SSL."
        echo "--------------------------"
        return 1
    fi
    
    # 3. Парсване и форматиране на датата
    # Конвертираме датата на изтичане в Unix Epoch време (секунди) за лесно изчисление
    EXPIRY_SEC=$(date -d "$EXPIRY_DATE_RAW" +%s 2>/dev/null)
    
    # Проверка дали датата е парсната успешно
    if [ $? -ne 0 ]; then
        log_alert "ERROR" "$DOMAIN" "Неуспешно парсване на датата: $EXPIRY_DATE_RAW"
        echo "--------------------------"
        return 1
    fi

    TODAY_SEC=$(date +%s)
    
    # Изчисляване на разликата в дни: (Секунди до изтичане - Секунди сега) / (Секунди в един ден)
    SECONDS_LEFT=$((EXPIRY_SEC - TODAY_SEC))
    DAYS_LEFT=$(echo "($SECONDS_LEFT / 86400)" | bc)

    EXPIRY_DATE_HUMAN=$(date -d "$EXPIRY_DATE_RAW" +'%Y-%m-%d %H:%M:%S %Z') # Human-readable format
    
    # 4. Дисплей на резултата и прилагане на прагове (Thresholds)
    
    # Проверка за изтекъл сертификат (Days Left < 0)
    if [ "$DAYS_LEFT" -lt 0 ]; then
        log_alert "CRITICAL" "$DOMAIN" "СЕРТИФИКАТЪТ Е ИЗТЕКЪЛ преди $DAYS_LEFT дни! (Изтекъл на: $EXPIRY_DATE_HUMAN)"
    # Проверка за CRITICAL праг (e.g., < 7 дни)
    elif [ "$DAYS_LEFT" -le "$CRITICAL_DAYS" ]; then
        log_alert "CRITICAL" "$DOMAIN" "Сертификатът изтича след $DAYS_LEFT дни! (Дата на изтичане: $EXPIRY_DATE_HUMAN)"
    # Проверка за WARNING праг (e.g., < 30 дни)
    elif [ "$DAYS_LEFT" -le "$WARNING_DAYS" ]; then
        log_alert "WARNING" "$DOMAIN" "Сертификатът изтича след $DAYS_LEFT дни. (Дата на изтичане: $EXPIRY_DATE_HUMAN)"
    # Сертификатът е ОК
    else
        log_alert "OK" "$DOMAIN" "Сертификатът е валиден още $DAYS_LEFT дни. (Дата на изтичане: $EXPIRY_DATE_HUMAN)"
    fi
    
    echo "--------------------------"
}

# --- Основна Логика на Скрипта ---

echo "==================================================="
echo "     SSL/TLS Сертификат Checker (Bash Script)      "
echo "==================================================="

# Проверка дали конфиг файла съществува
if [ ! -f "$CONFIG_FILE" ]; then
    log_alert "ERROR" "$CONFIG_FILE" "Конфигурационният файл не е намерен!"
    exit 1
fi

# Четене на домейните ред по ред (Loop through domains)
# 'while read -r DOMAIN' гарантира, че домейните се четат правилно, дори и с whitespace.
while IFS= read -r DOMAIN || [[ -n "$DOMAIN" ]]; do
    # Пропускане на коментари и празни редове
    if [[ "$DOMAIN" =~ ^#.* ]] || [[ -z "$DOMAIN" ]]; then
        continue
    fi
    
    # Изпълняване на проверката за домейна
    check_ssl_expiry "$DOMAIN"

done < "$CONFIG_FILE"

echo "Проверката приключи."
