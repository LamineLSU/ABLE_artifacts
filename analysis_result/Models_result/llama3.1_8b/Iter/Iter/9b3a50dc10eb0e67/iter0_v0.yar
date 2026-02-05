rule Bypass_Sample {
    meta:
        description = "Evasion bypass rule"
        cape_options = "bp0=$pattern1+0,action0=skip,bp1=$pattern2+0,action1=skip,bp2=$pattern3+0,action2=skip,count=0"

    strings:
        $pattern1 = { E8 D1 FF FF FF CA 00 40 3B 85 }
        $pattern2 = { FF 15 5C E0 04 00 CA DD 00 40 E0 5C }
        $pattern3 = { FF 15 A8 01 B8 00 CA DD 00 B8 01 A8 }

    condition:
        any of them
}