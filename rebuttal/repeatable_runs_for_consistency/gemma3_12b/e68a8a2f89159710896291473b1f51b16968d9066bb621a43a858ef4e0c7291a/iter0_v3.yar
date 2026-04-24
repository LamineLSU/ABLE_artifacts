rule Bypass_Sample
{
    meta:
        description = "Evasion bypass rule"
        cape_options = "bp0=$pattern0+0,action0=skip,bp1=$pattern1+0,action1=skip,bp2=$pattern2+0,action2=skip,count=0"

    strings:
        $pattern0 = { 85 C0 74 12 6A 5B 5A 8B CE E8 25 05 00 00 }
        $pattern1 = { 50 53 68 40 11 2F 01 33 C9 E8 4B 17 00 00 }
        $pattern2 = { 8B 40 68 8B 4D FC 5F 5E 33 CD 5B E8 57 26 00 00 }

    condition:
        any of them
}