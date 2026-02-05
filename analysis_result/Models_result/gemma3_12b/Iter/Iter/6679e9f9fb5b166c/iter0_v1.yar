rule Bypass_Sample
{
    meta:
        description = "Evasion bypass rule"
        cape_options = "bp0=$pattern0+0,action0=skip,bp1=$pattern1+0,action1=skip,bp2=$pattern2+0,action2=skip,count=0"

    strings:
        $pattern0 = { 6A 00 55 8B 85 E8 FE FF FF }
        $pattern1 = { 8B 85 E8 FE FF FF 8B 00 55 }
        $pattern2 = { 8D 85 80 FD FF FF 33 C0 E8 A5 91 FE FF }

    condition:
        any of them
}