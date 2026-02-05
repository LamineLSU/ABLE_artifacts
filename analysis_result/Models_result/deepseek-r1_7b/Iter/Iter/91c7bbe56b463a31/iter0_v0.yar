rule Bypass_Sample
{
    meta:
        description = "Evasion bypass rules targeting specific memory accesses"
        cape_options = "bp0=$pattern0+0,action0=skip,bp1=$pattern1+0,action1=skip,bp2=$pattern2+0,action2=skip,count=0"

    strings:
        $pattern0 = { 6A ?? 5A 8B CE E8 ?? ?? ?? ?? 85 C0 }
        $pattern1 = { FF 15 AC E0 42 00 8B EC 31 42 00 ?? ?? F0 }
        $pattern2 = { FF 15 8C 0A 68 02 00 00 02 FF D6 ?? }

    condition:
        any of them
}