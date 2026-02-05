rule Bypass_Sample
{
    meta:
        description = "Evasion bypass rule"
        cape_options = "bp0=$pattern0+0,action0=skip,bp1=$pattern1+0,action1=skip,bp2=$pattern2+0,action2=skip,count=0"

    strings:
        $pattern0 = { 85 C0 50 FF 15 2C A1 B5 00 }
        $pattern1 = { E8 C8 FF FF FF 59 FF 15 AC B0 41 00 }
        $pattern2 = { 85 C0 E8 25 05 00 00 85 C0 }

    condition:
        any of them
}