rule Bypass_Sample
{
    meta:
        description = "Evasion bypass rule"
        cape_options = "bp0=$pattern0+0,action0=skip,bp1=$pattern1+0,action1=skip,bp2=$pattern2+0,action2=skip,count=0"

    strings:
        $pattern0 = { 6A ?? 5A 8B CE E8 25 05 00 00 85 C0 }
        $pattern1 = { 85 C0 74 12 8D 95 F0 FE FF FF 89 9D F0 FE FF FF }
        $pattern2 = { BA 04 01 00 00 03 C3 B9 42 8C F8 00 50 }

    condition:
        any of them
}