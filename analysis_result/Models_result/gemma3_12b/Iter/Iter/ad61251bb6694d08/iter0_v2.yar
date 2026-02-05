rule Bypass_Sample
{
    meta:
        description = "Evasion bypass rule"
        cape_options = "bp0=$pattern0+0,action0=skip,bp1=$pattern1+0,action1=skip,bp2=$pattern2+0,action2=skip,count=0"

    strings:
        $pattern0 = { 53 6A 40 53 68 40 11 15 01 33 C9 E8 B3 03 00 00 A1 88 85 15 01 }
        $pattern1 = { FF 15 2C A1 15 01 33 FF 8B C7 EB 03 8D 43 01 8B 4D FC 5F 5E 33 CD 5B E8 57 26 00 00 }
        $pattern2 = { 85 C0 74 12 6A 5B 5A 8B CE E8 25 05 00 00 85 C0 0F 84 33 FD FF FF }

    condition:
        any of them
}