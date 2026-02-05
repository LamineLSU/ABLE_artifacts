rule EvasionBypass {
    meta:
        description = "Evasion bypass patterns for sandbox analysis"
        cape_options = "bp0=$pattern0+0,action0=skip,bp1=$pattern1+0,action1=skip,bp2=$pattern2+0,action2=skip,count=0"

    strings:
        $pattern0 = { 85 C0 74 12 6A 5B 5A 8B CE E8 25 05 00 00 0F 84 33 FD FF FF 00 97 66 7F FF 15 2C A1 97 00 }
        $pattern1 = { 85 C0 74 12 6A 5B 5A 8B CE E8 74 FA FF FF 0F 84 33 FD FF FF 00 97 5C 17 FF 15 2C A1 1A 00 }
        $pattern2 = { 85 C0 74 12 6A 5B 5A 8B CE E8 B3 03 00 00 0F 84 33 FD FF FF 00 97 6C E0 FF 15 2C A1 A8 00 }
    condition:
        any of them
}