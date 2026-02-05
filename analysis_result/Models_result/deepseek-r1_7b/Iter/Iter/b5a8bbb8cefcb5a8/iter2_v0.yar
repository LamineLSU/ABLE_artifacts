rule Bypass_Sample {
    meta:
        description = "Evasion bypass rule"
        cape_options = "bp0=$pattern0,action0=skip,bp1=$pattern1,action1=skip,bp2=$pattern2,action2=skip,count=0"

    strings:
        $pattern0 = { 55 8B EC FF 75 08 E8 C8 FF }
        $pattern1 = { 55 8B EC 99 0E FF 75 08 }
        $pattern2 = { 55 8B E0 FF 75 08 }

    condition:
        any of them
}