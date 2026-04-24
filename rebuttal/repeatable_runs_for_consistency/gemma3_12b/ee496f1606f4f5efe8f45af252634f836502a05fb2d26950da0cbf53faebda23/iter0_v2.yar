rule Bypass_Sample
{
    meta:
        description = "Evasion bypass rule"
        cape_options = "bp0=$pattern0+0,action0=skip,bp1=$pattern1+0,action1=skip,bp2=$pattern2+0,action2=skip,count=0"

    strings:
        $pattern0 = { 6A 00 83 7D FC 00 75 08 FF 15 88 7C 42 00 }
        $pattern1 = { 85 C0 74 05 E8 93 D7 00 00 FF 15 88 7C 42 00 }
        $pattern2 = { 6A 00 FF 15 88 7C 42 00 8B E5 5D C3 }

    condition:
        any of them
}