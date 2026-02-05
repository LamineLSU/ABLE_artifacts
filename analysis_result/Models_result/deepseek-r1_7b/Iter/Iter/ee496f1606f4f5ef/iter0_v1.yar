rule Bypass_Sample {
    meta:
        description = "Evasion bypass rule"
        cape_options = "bp0=$pattern0+0,action0=skip,bp1=$pattern1+0,action1=skip,bp2=$pattern2+0,action2=skip,count=0"

    strings:
        $pattern0 = { 2B 5F FF 15 88 7C 42 00 }
        $pattern1 = { 6A 5E 74 FF C0 7C 42 00 }
        $pattern2 = { 8B 55 FF 15 64 7D 42 00 }

    condition:
        any of them
}