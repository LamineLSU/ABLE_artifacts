rule Bypass_Sample_1
{
    meta:
        description = "Evasion bypass rule"
        cape_options = "bp0=$pattern0+0,action0=skip,bp1=$pattern1+0,action1=skip,bp2=$pattern2+0,action2=skip,count=0"

    strings:
        $pattern0 = { 53 FF 15 2C A1 B9 00 }
        $pattern1 = { 50 E8 E3 FA FF FF }
        $pattern2 = { 33 C9 E8 4B 17 00 00 }

    condition:
        any of them
}