rule Bypass_Sample_Evolved
{
    meta:
        description = "Evasion bypass rule - evolved with multiple strategies"
        cape_options = "bp0=$pattern0+0,action0=skip,bp1=$pattern1+0,action1=skip,bp2=$pattern2+0,action2=skip,count=0"

    strings:
        $pattern0 = { 85 C0 0F 84 33 FD FF FF 74 12 }
        $pattern1 = { 6A 5B 5A E8 4B 17 00 00 }
        $pattern2 = { 8B CE E8 E3 FA FF FF }
    condition:
        (any of them)
}

YARA_PATTERNS:
pattern0: [0x000C617A, 0x000C617C, 0x000C617E, 0x000C6180, 0x000C6181, 0x000C6183]
pattern1: [0x000C617A, 0x000C617C, 0x000C617E, 0x000C6180, 0x000C6181, 0x000C6183, 0x000C618A]
pattern2: [0x000C617A, 0x000C617C, 0x000C617E, 0x000C6180, 0x000C6181, 0x000C6183, 0x000C618A]