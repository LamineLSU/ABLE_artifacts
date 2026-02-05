rule Bypass_Sample
{
    meta:
        description = "Evasion bypass detection"
        cape_options = "bp0=$pattern0+0,action0=skip,bp1=$pattern1+0,action1=skip,bp2=$pattern2+0,count=0"

    strings:
        $pattern0 = { 6A 5A 8B CE E8 ?? }
        $pattern1 = { FF 75 08 ?? .C 4 ?? E8 C8 FF FF }
        $pattern2 = { 6A ?? .C E ?? E8 C8 FF FF }

    condition:
        any of them
}