rule Bypass_Evasion {
    meta:
        description = "Evasion bypass detection rules targeting specific instruction sequences"
        cape_options = "bp0=$pattern0+0,action0=skip,bp1=$pattern1+0,action1=skip,bp2=$pattern2+0,action2=skip,count=0"

    strings:
        $pattern0 = { 85 C0 0F 84 33 DB E8 CE 01 31 66 7F }     // 12 bytes
        $pattern1 = { 6A 5B 5A 0F 84 33 C9 E8 4B 17 00 00 8B E5 FF 15 2C A1 A4 00 33 DB C3 00 A4 6C E0 } // 16 bytes
        $pattern2 = { 00 A4 6C 17 E8 0D 0C 00 00 00 A4 6E 2A FF 15 2C A1 A4 00 C3 00 A4 6C E0 }          // 13 bytes

    condition:
        any_of_them
}