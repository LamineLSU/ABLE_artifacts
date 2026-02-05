rule Bypass_Sample
{
    meta:
        description = "Evasion bypass rule"
        cape_options = "bp0=$pattern0+0,action0=skip,bp1=$pattern1+0,action1=skip,bp2=$pattern2+0,action2=skip,count=0"

    strings:
        $pattern0 = { FF 15 B4 92 39 00 83 F8 20 7E 07 FF 57 }
        $pattern1 = { 8D 4D E8 E8 48 C2 FE FF 8D 4D A0 E8 3E 61 FE FF }
        $pattern2 = { 5F 5E 8B E5 C3 5D }

    condition:
        any of them
}