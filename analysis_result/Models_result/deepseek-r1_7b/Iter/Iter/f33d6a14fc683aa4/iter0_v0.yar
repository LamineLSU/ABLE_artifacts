rule Bypass_Evasion {
    meta:
        description = "Evasion bypass detection"
        cape_options = "bp0=$pattern0+0,action0=skip,bp1=$pattern1+0,action1=skip,bp2=$pattern2+0,action2=skip,count=0"

    strings:
        $pattern0 = { 85 C0 FF C0 8B 45 5A E8 CE 01 00 6A 40 BA 53 E8 C8 FF FF FF 75 08 8B E5 F0 FF FF 15 2C A1 A3 00 ?? ?? ?? 85 C0 0F 84 33 FD FF FF 74 07 0F 84 33 FD FF FF 8D 43 01 EB BA 21 05 00 00 53 } 
        $pattern1 = { FF 15 2C A1 A3 00 8B 45 F0 FF FF 75 08 8B E5 F0 FF FF 15 88 A0 F8 00 33 DB E8 4B 17 00 00 A1 88 85 F8 00 68 40 11 F8 00 ?? ?? }
        $pattern2 = { 8B E5 F0 FF FF 15 2C A1 A3 00 33 DB E8 4B 17 00 00 A1 88 85 F8 00 68 40 11 F8 00 ?? ?? }

    condition:
        any of them
}