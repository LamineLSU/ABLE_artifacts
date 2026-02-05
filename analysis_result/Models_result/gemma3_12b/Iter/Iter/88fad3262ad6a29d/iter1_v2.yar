rule Bypass_Sample
{
    meta:
        description = "Evasion bypass rule"
        cape_options = "bp0=$pattern0+0,action0=skip,bp1=$pattern1+0,action1=skip,bp2=$pattern2+0,action2=skip,count=0"

    strings:
        $pattern0 = { 85 C0 74 16 E8 70 84 FF FF }
        $pattern1 = { 85 C0 74 08 6A 00 FF 15 0C F2 47 00 }
        $pattern2 = { 6A 00 FF 15 0C F2 47 00 E8 76 E9 FF FF }

    condition:
        any of them
}