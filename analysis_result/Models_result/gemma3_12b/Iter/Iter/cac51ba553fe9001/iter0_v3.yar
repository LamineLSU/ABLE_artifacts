rule Bypass_Sample
{
    meta:
        description = "Evasion bypass rule"
        cape_options = "bp0=$pattern0+0,action0=skip,bp1=$pattern1+0,action1=skip,bp2=$pattern2+0,action2=skip,count=0"

    strings:
        $pattern0 = { 33 FF 8B C7 EB 03 8D 43 01 5F 5E 33 CD 5B E8 57 26 00 00 }
        $pattern1 = { 85 C0 0F 84 33 FD FF FF 8B 85 F0 FE FF FF }
        $pattern2 = { 85 C0 0F 84 33 FD FF FF 8D 95 F0 FE FF FF }

    condition:
        any of them
}