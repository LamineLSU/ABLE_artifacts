rule Bypass_Sample
{
    meta:
        description = "Evasion bypass rule"
        cape_options = "bp0=$pattern0+0,action0=skip,bp1=$pattern1+0,action1=skip,bp2=$pattern2+0,action2=skip,count=0"

    strings:
        $pattern0 = { 6A ?? 5A 8B CE E8 ?? ?? ?? ?? 85 C0 }
        $pattern1 = { FF 15 C0 92 44 00 83 F8 20 7E 07 }
        $pattern2 = { 8D 4D B4 E8 B3 77 FF FF 8D 4D CC }

    condition:
        any of them
}