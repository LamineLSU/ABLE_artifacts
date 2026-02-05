rule Bypass_Evasion {
    meta:
        description = "Evasion bypass detection rules"
        cape_options = "bp0=$pattern0+0,action0=skip,bp1=$pattern1+0,action1=skip,bp2=$pattern2+0,action2=skip,count=0"

    strings:
        $pattern0 = { 51 68 FF 75 08 FF C0 FF 45 5C 3C 5E 5A 79 CA CB EC FF 6B }
        $pattern1 = { E8 FF 75 08 FF CE 20 FF 5F 0D 6A 00 FF 15 CC 01 6E 01 CC }
        $pattern2 = { FF 75 F8 FF 45 EC FF 8C FF 9F FF 3C FF 58 FF D0 FF B9 }

    condition:
        any of them
}