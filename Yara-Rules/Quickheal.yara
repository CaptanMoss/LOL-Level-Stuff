rule Quickheal 
{
    meta:
        description = "Detects potential malicious usage of certain APIs"
        author = "Büşra Yenidoğan"
        reference = "Custom rule based on provided API list"
        date = "2024-11-24"
    
    strings:
        $api1 = "GetProcessAffinityMask" ascii
        $api2 = "SetProcessAffinityMask" ascii
        $api3 = "SetThreadAffinityMask" ascii
        $api4 = "CharUpperBuffW" ascii
        $api5 = "CredEnumerateA" ascii
        $api6 = "ShellExecuteW" ascii
        $api7 = "PathGetArgsW" ascii
        $api8 = "NetUserGetInfo" ascii
        $api9 = "GetAdaptersInfo" ascii
        $api10 = "CryptUnprotectData" ascii
        
        $str = "GetOfficeDatatal" ascii
    
    condition:
        uint16(0) == 0x5A4D and $str and 7 of ($api * )

}