rule Bypass_Sample
{
    meta:
        description = "Evasion bypass rule"
        cape_options = "bp0=$pattern0+0,action0=skip,bp1=$pattern1+0,action1=skip,bp2=$pattern2+0,action2=skip,count=0"

    strings:
        $pattern0 = { E8 E3 FA FF FF FF 50 E9 B5 FC FF FF FF }
        $pattern1 = { BA 21 05 00 00 53 6A 40 }
        $pattern2 = { FF 15 8C E1 F1 10 50 FF 15 40 E1 F1 10 }

    condition:
        any of them
}