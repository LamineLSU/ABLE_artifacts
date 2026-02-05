rule Bypass_Sample {
    meta:
        description = "Evasion bypass rule"
        cape_options = "bp0=$pattern0+0,action0=skip,bp1=$pattern1+0,action1=skip,bp2=$pattern2+0,action2=skip,count=0"

    strings:
        $pattern0 = { 20 6A ?? 5B 56 57 FF }
        $pattern1 = { 20 FF EE CE 8D ?? F8 FE FF FF 5F 6A ?? }
        $pattern2 = { 20 FF EE CE 33 C0 ?? 8B 4D FC E8 }

    condition:
        any of them
}