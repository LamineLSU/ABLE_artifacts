rule Bypass_Sample {
    meta:
        description = "Evasion bypass rule"
        cape_options = "bp0=$pattern0+0,action0=skip,bp1=$pattern1+0,action1=skip,bp2=$pattern2+0,count=0"

    strings:
        $pattern0 = { 8B EC E8 C8 FF FF FF ?? }
        $pattern1 = { FF C9 E8 C8 FF FF }
        $pattern2 = { 5A F7 E8 C8 FF FF }

    condition:
        any of them
}