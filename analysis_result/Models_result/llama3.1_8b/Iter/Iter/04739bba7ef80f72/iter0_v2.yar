rule Bypass_Sample
{
    meta:
        description = "Evasion bypass rule"
        cape_options = "bp0=$pattern0+0,action0=skip,bp1=$pattern1+0,action1=skip,bp2=$pattern2+0,action2=skip,count=0"

    strings:
        $pattern0 = { E8 EE 82 FF FF E8 89 E0 FF FF 85 C0 }
        $pattern1 = { E8 EE 82 FF FF E8 89 E0 FF FF 00 }
        $pattern2 = { E8 B7 F7 FF FF E8 89 E0 FF FF 85 C0 }

    condition:
        any of them
}