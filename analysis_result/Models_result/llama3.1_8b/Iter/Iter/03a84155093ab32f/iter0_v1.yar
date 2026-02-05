rule Bypass_Sample {
    meta:
        description = "Evasion bypass rule"
        cape_options = "bp0=$pattern0+0,action0=skip,bp1=$pattern1+0,action1=skip,bp2=$pattern2+0,action2=skip,count=0"

    strings:
        $pattern0 = { 8B 45 10 83 C4 14 52 8B 16 50 51 FF D2 5E 5D C3 }
        $pattern1 = { E8 ?? ?? ?? ?? 6A 00 6A 35 6A 00 56 51 E8 44 09 00 00 E8 44 09 00 00 }
        $pattern2 = { FF D2 5E 5D C3 85 C0 0F 84 ?? ?? ?? ?? 8B 45 ?? }

    condition:
        any of them
}