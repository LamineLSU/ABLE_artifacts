rule Bypass_Sample_Evolved {
    meta:
        description = "Evasion bypass rule - evolved"
        cape_options = "bp0=$pattern0+0,action0=skip,bp1=$pattern1+0,action1=skip,bp2=$pattern2+0,action2=skip,count=0"

    strings:
        $pattern0 = { 8B 40 68 60 8B EC 6C 75 10 7A }
        $pattern1 = { E8 6F 74 00 00 3E 55 2D FF 75 08 9C }
        $pattern2 = { 85 C0 84 8B EC 6C 83 F8 1C 74 12 6D 51 29 FF 00 00 }

    condition:
        any of them
}