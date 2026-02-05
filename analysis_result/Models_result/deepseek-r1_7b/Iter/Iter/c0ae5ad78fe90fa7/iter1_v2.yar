rule Bypass_Sample_Evolved
{
    meta:
        description = "Evasion bypass rule - targeted conditional exit checks"
        cape_options = "bp0=$pattern0+0,action0=skip,bp1=$pattern1+0,action1=skip,bp2=$pattern2+0,action2=skip,count=0"

    strings:
        $pattern0 = { 8B FF 55 8B EC FF 75 08 }
        $pattern1 = { E8 C8 FF FF FF FF 75 08 FF 15 64 10 41 00 }
        $pattern2 = { 3D 00 10 00 00 0F 82 }
}

condition:
    (any of the patterns match)
}