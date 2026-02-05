rule Bypass_Sample
{
    meta:
        description = "Evasion bypass rule"
        cape_options = "bp0=$pattern0+0,action0=skip,bp1=$pattern1+0,action1=skip,bp2=$pattern2+0,action2=skip,count=0"

    strings:
        $pattern0 = { 6A 5B 5A 8B CE E8 25 05 00 00 85 C0 }
        $pattern1 = { 8B 85 F0 FE FF FF 8D 8D F8 FE FF FF 03 C3 B9 42 8C 2F 01 50 E8 E3 FA FF FF }
        $pattern2 = { FF 15 2C A1 2F 01 33 FF 8B C7 EB 03 8D 43 01 5F 5E 33 CD 5B E8 57 26 00 00 }

    condition:
        any of them
}