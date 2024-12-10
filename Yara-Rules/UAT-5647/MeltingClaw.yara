rule MeltingClaw 
{
    meta:
        description = "Detects a specific hex dump pattern with function bytes and potential malicious usage of certain APIs "
        author = "Büşra Yenidoğan"
        date = "2024-11-24"
        
    strings:
        $obfuscation_function = {
            4C 8B 12 33 C0 4C 8B C2 4C 8B C9 4D 85 D2 75 33 4C 8D 5A 08 49 39 03 75 2A 48 8D 5A 10 48 39 03 75 21 48 8D 7A 18 48 39 07 75 18 49 BA ?? 30 3A ?? ?? 3A ?? ?? 4C 8B FF 4C 89 12 4C 8B F3 49 8B F3 EB 15 48 8D 72 08 4C 8D 72 10 4C 8B DE 4C 8D 7A 18 49 8B DE 49 8B FF 48 B8 AB AA AA AA AA AA AA AA 49 8B CA 49 F7 E2 48 D1 EA 48 8D 04 52 48 2B C8 FE C1 0F B6 D1 83 EA 01 74 24 83 EA 01 74 12 83 FA 01 75 62 49 8B D0 49 8B C9 E8 ?? ?? 00 00 EB 55 49 8B D0 49 8B C9 E8 ?? ?? 00 00 EB 48 B8 3F 88 FE DE 49 C7 06 21 2A 01 00 48 89 06 41 0F BE C2 6B C8 3F 49 C7 07 00 01 00 00 80 C1 21 41 88 09 49 FF C1
        }

        $custom_encryption_function = {
            48 89 6A 08 4C 8B F1 33 DB 48 8D 4C 24 20 33 D2 44 8B C5 8B F3 E8 ?? ?? 00 00 8B C3 88 44 04 20 48 FF C0 48 3B C5 72 F4 4C 8B 0F 4C 8B C3 42 8A 54 04 20 41 8A C8 80 E1 07 49 8B C1 C0 E1 03 48 D3 E8 02 C2 40 02 C6 0F B6 F0 32 54 34 20 42 88 54 04 20 30 54 34 20 8A 44 34 20 42 30 44 04 20 49 FF C0 4C 3B C5 72 C6 4C 8B C3 48 8B D3 FE C3 0F B6 DB 8A 4C 1C 20 41 8D 04 08 44 0F B6 C0 42 32 4C 04 20 88 4C 1C 20 42 30 4C 04 20 42 8A 44 04 20 32 44 1C 20 0F BE C8 88 44 1C 20 42 0F BE 44 04 20 03 C8 81 E1 FF 00 00 80 7D 0A FF C9 81 C9 00 FF FF FF FF C1 0F B6 C1 8A 4C 04 20 41 88 0C 16 48 FF C2 48 83 FA ?? 72 A3 48 8B 8C 24 20 01 00 00
        }

        $shifting_function = {
            4C 8B 02 4C 8B D2 48 8B F9 48 C7 42 08 16 00 00 00 48 C7 42 10 09 00 00 00 45 33 C9 48 C7 42 18 0D 00 00 00 49 8B 4A 08 49 8B C0 48 D3 E0 32 DB 49 8B 4A 10 4C 33 C0 49 8B C0 48 D3 E8 49 8B 4A 18 4C 33 C0 49 8B C0 48 D3 E0 4C 33 C0 45 32 DB 41 0F B6 CB 49 8B D0 C1 E1 03 41 FE C3 48 D3 EA 32 DA 41 80 FB 08 72 E8 41 88 1C 39 49 FF C1 49 83 F9 ?? 72 AF 48 8B 5C 24 08
        }

        $execute_function = {
            41 5B 48 83 C4 08 48 8B 44 24 18 4C 8B 10 4C 89 14 24
        }

        $trem1 = "trem1" wide
        $trem3 = "trem3" wide
        $state1 = "state1" wide
        $state3 = "state3" wide
        $reg1 = "RegCreateKeyExA"
        $reg2 = "RegSetValueExW"
        $reg3 = "RegCloseKey"

        $post = "POST" wide
        $win1 = "WinHttpGetProxyForUrl"
        $win2 = "WinHttpReceiveResponse"
        $win3 = "WinHttpSendRequest"
        $win4 = "WinHttpGetIEProxyConfigForCurrentUser"
        $win5 = "WinHttpReadData"
        $win6 = "WinHttpConnect"
        $win7 = "WinHttpCloseHandle"
        $win8 = "WinHttpOpen"
        $win9 = "WinHttpSetOption"
        $win10 = "DnsFree"
        $win11 = "DnsQuery_A"
    
    condition:
        uint16(0) == 0x5A4D and ($obfuscation_function and $custom_encryption_function and $shifting_function and $execute_function) and ((($trem1 and $trem3) or ($state1 and $state3)) and ( 2 of ($reg*))) and (($post and (all of ($win*))))

}