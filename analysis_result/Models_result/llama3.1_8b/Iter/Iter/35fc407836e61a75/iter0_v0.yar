rule Bypass_Sample {
    meta:
        description = "Evasion bypass rule"
        cape_options = "bp0=$pattern1+0,action0=skip,bp1=$pattern2+0,action1=skip,bp2=$pattern3+0,action2=skip,count=0"

    strings:
        $pattern1 = { FF 15 AC B0 41 00 FF 15 2C A1 0A 01 }
        $pattern2 = { 8D 95 F0 FE FF FF 89 9D F0 FE FF FF }
        $pattern3 = { E8 C8 FF FF FF E8 ?? ?? ?? ?? }

    condition:
        any of them
}