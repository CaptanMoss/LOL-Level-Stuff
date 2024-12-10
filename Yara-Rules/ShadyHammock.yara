rule ShadyHammock 
{
    meta:
        description = "Detects a specific hex dump pattern with function bytes and potential malicious usage of certain APIs "
        author = "Büşra Yenidoğan"
        date = "2024-11-24"
        
    strings:
        $obfuscation_function = {
            4C 8B 12 33 C0 4C 8B C2 4C 8B C9 4D 85 D2 75 33 4C 8D 5A 08 49 39 03 75 2A 48 8D 5A 10 48 39 03 75 21 48 8D 7A 18 48 39 07 75 18 49 BA ?? ?? 3A ?? ?? 3A ?? ?? 4C 8B FF 4C 89 12 4C 8B F3 49 8B F3 EB 15 48 8D 72 08 4C 8D 72 10 4C 8B DE 4C 8D 7A 18 49 8B DE 49 8B FF 48 B8 AB AA AA AA AA AA AA AA 49 8B CA 49 F7 E2 48 D1 EA 48 8D 04 52 48 2B C8 FE C1 0F B6 D1 83 EA 01 74 24 83 EA 01 74 12 83 FA 01 75 61 49 8B D0 49 8B C9 E8 ?? ?? 00 00 EB 54 49 8B D0 49 8B C9 E8 ?? ?? 00 00 EB 47 41 0F BE C2 6B C8 6D 48 C7 06 6D 4E C6 41 49 C7 06 39 30 00 00 49 C7 07 00 01 00 00 80 C1 39 41 88 09 49 FF C1
        }

        $custom_encryption_function = {
            ?? 89 ?? 08 ?? 8B ?? 33 DB 48 8D 4C 24 20 33 D2 ?? 8B ?? 8B F3 E8 ?? ?? 00 00 8B C3 88 44 04 20 48 FF C0 ?? 3B ?? 72 F4 4C 8B 0F 4C 8B C3 42 8A 54 04 20 41 8A C8 80 E1 07 49 8B C1 C0 E1 03 48 D3 E8 02 C2 40 02 C6 0F B6 F0 32 54 34 20 42 88 54 04 20 30 54 34 20 8A 44 34 20 42 30 44 04 20 49 FF C0 ?? 3B ?? 72 C6 4C 8B C3 48 8B D3 FE C3 0F B6 DB 8A 4C 1C 20 41 8D 04 08 44 0F B6 C0 42 32 4C 04 20 88 4C 1C 20 42 30 4C 04 20 42 8A 44 04 20 32 44 1C 20 0F BE C8 88 44 1C 20 42 0F BE 44 04 20 03 C8 81 E1 FF 00 00 80 7D 0A FF C9 81 C9 00 FF FF FF FF C1 0F B6 C1 8A 4C 04 20 
        }

        $shifting_function = {
            48 c7 42 08 0d 00 00 00 48 c7 42 10 07 00 00 00 45 33 c9 48 c7 42 18 11 00 00 00 49 8b 4a 08 49 8b c0 48 d3 e0 32 db 49 8b 4a 10 4c 33 c0 49 8b c0 48 d3 e8 49 8b 4a 18 4c 33 c0 49 8b c0 48 d3 e0 4c 33 c0 45 32 db 41 0f b6 cb 49 8b d0 c1 e1 03 41 fe c3 48 d3 ea 32 da 41 80 fb 08 72 e8 41 88 1c 39 49 ff c1 49 83 f9 08 72 af 48 8b 5c 24 08 
        }

        $ws1 = "closesocket" ascii
        $ws2 = "listen" ascii
        $ws3 = "WSAAccept" ascii
        $ws4 = "bind" ascii
        $ws5 = "inet_addr" ascii
        $ws6 = "socket" ascii
        $ws7 = "recv" ascii
        $ws8 = "htons" ascii
        $ws9 = "WSAStartup" ascii
        $adv1 = "RegOpenKeyExW" ascii
        $adv2 = "RegDeleteKeyW" ascii
        $adv3 = "RegCloseKey" ascii
        $adv4 = "RegQueryValueExW" ascii
        $ip = "127.0.0.1" ascii
    condition:
        uint16(0) == 0x5A4D and (($shifting_function and $obfuscation_function) or $custom_encryption_function) and (2 of ($ws * ) and all of ($adv * )) and $ip

}