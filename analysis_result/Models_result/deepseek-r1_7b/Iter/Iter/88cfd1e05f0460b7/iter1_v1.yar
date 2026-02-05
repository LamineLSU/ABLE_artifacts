rule Bypass_Sample_Evolved
{
    meta:
        description = "Evasion bypass targeting conditional checks and unique sequences"
        cape_options = "bp0=$pattern0+0,action0=skip,bp1=$pattern1+0,action1=skip,bp2=$pattern2+0,action2=skip,count=0"

    strings:
        $pattern0 = { 85 C0 0F 84 74 12 8B CC FF 9E 74 12 }
        $pattern1 = { 3D 00 10 00 00 00 00 00 0F 82 00 00 }
        $pattern2 = { 6A 5B 5A 8B CE E8 4B FF 74 FF 74 }

    condition:
        (any of these patterns match)
}