rule Bypass_Sample
{
    meta:
        description = "Evasion bypass rule"
        cape_options = "bp0=$pattern0+0,action0=skip,bp1=$pattern1+0,action1=skip,bp2=$pattern2+0,action2=skip,count=0"

    strings:
        $pattern0 = { 00 B6 C2 DC A8 01 }
        $pattern1 = { 00 B6 C2 E0 FF 75 08 }
        $pattern2 = { 00 40 3B B9 FF 15 5C E0 40 00 }

    condition:
        any of them
}