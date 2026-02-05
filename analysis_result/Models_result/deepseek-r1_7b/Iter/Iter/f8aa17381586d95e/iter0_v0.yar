rule Bypass_Evasion_Plugins {
    meta:
        description = "Bypass analysis for sandbox evasion in a virtual machine"
        cape_options = "bp0=$pattern0+0,action0=skip,bp1=$pattern1+0,action1=skip,bp2=$pattern2+0,action2=skip,count=0"

    strings:
        $pattern0 = { 00 41 AF 60 FF D2 55 8B EC 00 C4 14 05 A3 F8 C0 05 }
        $pattern1 = { 00 41 AF 60 FF D2 55 8B EC 00 C4 14 05 A3 F8 C0 06 A3 }
        $pattern2 = { 00 41 AF 60 FF D2 55 8B EC 00 C4 14 05 A3 F8 C0 07 40 8C E0 0C 41 }
}

condition:
    (any of the patterns match)
}