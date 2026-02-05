rule Bypass_Sample
{
    meta:
        description = "Evasion bypass rule"
        cape_options = "bp0=$pattern0+0,action0=skip,bp1=$pattern1+0,action1=skip,bp2=$pattern2+0,action2=skip,count=0"

    strings:
        $pattern0 = { 85 C0 74 12 6A 5B 5A 8B CE E8 25 05 00 00 }
        $pattern1 = { E8 74 FA E8 B3 03 8B 4D FC 5F 5E 33 CD 5B }
        $pattern2 = { FF 15 AC B0 41 00 8B 85 F0 FE FF FF 8D 95 F0 FE FF FF }

    condition:
        any of them
}