rule Bypass_Sample {
    meta:
        description = "Evasion bypass rule"
        cape_options = "bp0=$pattern0+0,action0=skip,bp1=$pattern1+0,action1=skip,bp2=$pattern2+0,action2=skip,count=0"

    strings:
        $pattern0 = { E8 ?? ?? ?? ?? FA FF FF FA FF FF }
        $pattern1 = { 64 A1 30 00 00 00 EA DD ?? EA ?? }
        $pattern2 = { C1 E8 08 EA ?? EA 01 ?? FF 15 8C E1 1E 00 CA ?? }

    condition:
        any of them
}