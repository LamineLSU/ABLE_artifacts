rule Bypass_Sample {
    meta:
        description = "Evasion bypass rule"
        cape_options = "bp0=$pattern0+0,action0=skip,bp1=$pattern1+0,action1=skip,bp2=$pattern2+0,action2=skip,count=0"

    strings:
        $pattern0 = { 83 BD 60 F9 FF FF 01 75 23 E8 ?? ?? ?? ?? }
        $pattern1 = { 83 BD 60 F9 FF FF 01 85 C0 0F 84 ?? ?? ?? ?? }
        $pattern2 = { E8 8E 07 00 00 55 8B EC 81 C4 00 FC FF }

    condition:
        any of them
}