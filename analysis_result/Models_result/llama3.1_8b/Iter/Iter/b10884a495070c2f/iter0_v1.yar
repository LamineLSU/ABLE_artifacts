rule Bypass_Sample {
    meta:
        description = "Evasion bypass rule"
        cape_options = "bp0=$pattern1+0,action0=skip,bp1=$pattern2+0,action1=skip,bp2=$pattern3+0,action2=skip,count=0"

    strings:
        $pattern1 = { 74 1B 90 8B 45 ?? }
        $pattern2 = { FF 15 03 04 00 ?? FF EC F4 FF FF }
        $pattern3 = { 75 0E 53 E8 6B F3 FF FF }

    condition:
        any of them
}