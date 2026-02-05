rule Bypass_Sample
{
    meta:
        description = "Evasion bypass rule"
        cape_options = "bp0=$pattern0+0,action0=skip,bp1=$pattern1+0,action1=skip,bp2=$pattern2+0,action2=skip,count=0"

    strings:
        $pattern0 = { FF 15 D8 54 41 00 FF 75 08 FF 15 9C 54 44 10 }
        $pattern1 = { 6A 00 FF 75 08 FF 15 94 54 44 10 }
        $pattern2 = { 83 7D 10 00 75 32 68 00 C2 41 00 }

    condition:
        any of them
}