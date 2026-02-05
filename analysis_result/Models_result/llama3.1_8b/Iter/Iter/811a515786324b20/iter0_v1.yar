rule Bypass_Sample {
    meta:
        description = "Evasion bypass rule"
        cape_options = "bp0=$pattern0+0,action0=skip,bp1=$pattern1+0,action1=skip,bp2=$pattern2+0,action2=skip,count=0"

    strings:
        $pattern0 = { E8 F5 B9 FE FF BA 03 00 00 00 0A ?? ?? ED 00 00 00 03 }
        $pattern1 = { 89 5E 8F EF FF 8B 85 7C FD FF FF EA EA DD EB 00 00 02 84 }
        $pattern2 = { 33 C0 89 85 F0 FE FF FF EA DD EB 00 00 01 10 }

    condition:
        any of them
}