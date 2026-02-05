rule Bypass_Sample {
    meta:
        description = "Evasion bypass rule"
        cape_options = "bp0=$pattern0+0,action0=skip,bp1=$pattern1+0,action1=skip,bp2=$pattern2+0,action2=skip,count=0"

    strings:
        $pattern0 = { 8B 45 14 8B 48 14 56 6A 35 6A 00 51 }
        $pattern1 = { 52 FF D0 5E 83 C4 14 52 FF D2 5E }
        $pattern2 = { 50 85 C0 0F 84 ?? ?? ?? ?? }

    condition:
        any of them
}