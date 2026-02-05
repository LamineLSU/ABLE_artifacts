rule Bypass_Sample_Evolved {
    meta:
        description = "Evasion bypass rule - specific decision points"
        cape_options = "bp0=$pattern0+0,action0=skip,bp1=$pattern1+0,action1=skip,bp2=$pattern2+0,action2=skip,count=0"

    strings:
        $pattern0 = { 00 42 7B 16 E8 C1 FF FF FF 00 42 7B 1A FF 75 08 }
        $pattern1 = { 00 42 7B 11 E8 C1 FF FF FF AD EA 00 00 FF FF 00 42 7B 1E 0F 3D 84 }
        $pattern2 = { 00 42 7B 0B DC AD 15 F4 00 00 }

    condition:
        any of them
}