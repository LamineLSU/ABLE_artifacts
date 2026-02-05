rule Bypass_Evasion {
    meta:
        description = "Evasion bypass detection rules targeting memory and stack manipulation"
        cape_options = "bp0=$pattern0+0,action0=skip,bp1=$pattern1+0,action1=skip,bp2=$pattern2+0,action2=skip,count=0"

    strings:
        $pattern0 = { 8B EC FF D2 8B 45 08 }
        $pattern1 = { 8B 55 14 E8 44 09 00 5E }
        $pattern2 = { 6A 35 8B 45 08 FF 00 8B EC FF D2 }

    condition:
        any of them
}