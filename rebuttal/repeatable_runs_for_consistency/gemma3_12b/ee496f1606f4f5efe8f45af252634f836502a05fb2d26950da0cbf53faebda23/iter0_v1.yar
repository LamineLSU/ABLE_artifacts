rule Bypass_Sample
{
    meta:
        description = "Evasion bypass rule"
        cape_options = "bp0=$pattern0+0,action0=skip,bp1=$pattern1+0,action1=skip,bp2=$pattern2+0,action2=skip,count=0"

    strings:
        $pattern0 = { 75 08 6A 00 FF 15 88 7C 42 00 }
        $pattern1 = { E8 74 FE FF FF 8B FF 00 E8 0D FF FF FF }
        $pattern2 = { 6A 00 FF 15 88 7C 42 00 }

    condition:
        any of them
}