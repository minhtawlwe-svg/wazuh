/*
    AGB custom YARA rules
    Repo: github.com/minhtawlwe-svg/wazuh (git-home/yara)
    Author: Ye Kyaw Han, Hsu Sandy Thein
    Merged into /var/ossec/yara/rules/index.yar by update-yara-rules.sh

    Add your own rules below or replace this file entirely.
    After updating, restart the Wazuh agent so AR scans use the new rules.
*/

// ---------------------------------------------------------------------------
// 1. EICAR test file - safe way to test the whole pipeline end to end
// ---------------------------------------------------------------------------
rule EICAR_Test_File
{
    meta:
        description = "EICAR antivirus test string (harmless, for pipeline testing)"
        severity = "test"
    strings:
        $eicar = "X5O!P%@AP[4\\PZX54(P^)7CC)7}$EICAR-STANDARD-ANTIVIRUS-TEST-FILE!$H+H*"
    condition:
        $eicar
}

// ---------------------------------------------------------------------------
// 2. XMRig / generic cryptominer
// ---------------------------------------------------------------------------
rule Cryptominer_XMRig
{
    meta:
        description = "XMRig Monero miner strings"
        severity = "high"
        mitre = "T1496"
    strings:
        $s1 = "xmrig" nocase
        $s2 = "stratum+tcp://" nocase
        $s3 = "stratum+ssl://" nocase
        $s4 = "cryptonight" nocase
        $s5 = "randomx" nocase
        $s6 = "pool.minexmr.com" nocase
        $s7 = "--donate-level" nocase
    condition:
        2 of them
}

// ---------------------------------------------------------------------------
// 3. RedLine stealer indicators
// ---------------------------------------------------------------------------
rule Stealer_RedLine_Generic
{
    meta:
        description = "RedLine infostealer common strings"
        severity = "high"
        mitre = "T1555"
    strings:
        $s1 = "RedLine" ascii wide
        $s2 = "ScanPasswords" ascii wide
        $s3 = "ScanBrowsers" ascii wide
        $s4 = "ScannedWallets" ascii wide
        $s5 = "GetCredentials" ascii wide
    condition:
        2 of them
}

// ---------------------------------------------------------------------------
// 4. Linux reverse shell one-liners dropped as scripts
// ---------------------------------------------------------------------------
rule Linux_Reverse_Shell_Script
{
    meta:
        description = "Common reverse shell one-liners in scripts"
        severity = "high"
        mitre = "T1059.004"
    strings:
        $a1 = "bash -i >& /dev/tcp/"
        $a2 = "rm -f /tmp/f;mkfifo /tmp/f"
        $a3 = "python -c 'import socket,subprocess,os"
        $a4 = "python3 -c 'import socket,subprocess,os"
        $a5 = "nc -e /bin/sh"
        $a6 = "nc -e /bin/bash"
        $a7 = "socket.SOCK_STREAM);s.connect"
    condition:
        any of them
}

// ---------------------------------------------------------------------------
// 5. Generic PHP webshell
// ---------------------------------------------------------------------------
rule PHP_Webshell_Generic
{
    meta:
        description = "Generic PHP webshell patterns (eval/system on request input)"
        severity = "high"
        mitre = "T1505.003"
    strings:
        $php = "<?php"
        $e1 = /eval\s*\(\s*\$_(GET|POST|REQUEST|COOKIE)/ nocase
        $e2 = /system\s*\(\s*\$_(GET|POST|REQUEST)/ nocase
        $e3 = /shell_exec\s*\(\s*\$_(GET|POST|REQUEST)/ nocase
        $e4 = /passthru\s*\(\s*\$_(GET|POST|REQUEST)/ nocase
        $e5 = "eval(base64_decode(" nocase
        $e6 = "eval(gzinflate(base64_decode(" nocase
    condition:
        $php and any of ($e*)
}

// ---------------------------------------------------------------------------
// 6. Metasploit / Meterpreter payloads
// ---------------------------------------------------------------------------
rule Metasploit_Meterpreter
{
    meta:
        description = "Meterpreter / Metasploit payload strings"
        severity = "critical"
        mitre = "T1219"
    strings:
        $s1 = "meterpreter" nocase
        $s2 = "metsrv.dll" nocase
        $s3 = "ReflectiveLoader" ascii
        $s4 = "metasploit" nocase
    condition:
        any of them
}

// ---------------------------------------------------------------------------
// 7. Mirai botnet variants
// ---------------------------------------------------------------------------
rule Botnet_Mirai_Generic
{
    meta:
        description = "Mirai botnet common strings"
        severity = "critical"
        mitre = "T1584.005"
    strings:
        $s1 = "/bin/busybox MIRAI"
        $s2 = "PMMV" fullword
        $s3 = "killer_kill_by_port"
        $s4 = "attack_udp_generic"
        $s5 = "attack_tcp_syn"
    condition:
        any of them
}

// ---------------------------------------------------------------------------
// 8. UPX-packed ELF in a user-writable location (suspicious, not conclusive)
// ---------------------------------------------------------------------------
rule Suspicious_UPX_Packed_ELF
{
    meta:
        description = "UPX packed ELF binary - common malware packer"
        severity = "medium"
        mitre = "T1027.002"
    strings:
        $upx1 = "UPX!"
        $upx2 = "$Info: This file is packed with the UPX"
    condition:
        uint32(0) == 0x464c457f and any of them
}

// ---------------------------------------------------------------------------
// 9. Ransomware notes (generic)
// ---------------------------------------------------------------------------
rule Ransomware_Note_Generic
{
    meta:
        description = "Common ransomware note phrases"
        severity = "critical"
        mitre = "T1486"
    strings:
        $s1 = "your files have been encrypted" nocase
        $s2 = "all your files are encrypted" nocase
        $s3 = "decrypt your files" nocase
        $s4 = "bitcoin wallet" nocase
        $s5 = "tor browser" nocase
    condition:
        2 of them
}
