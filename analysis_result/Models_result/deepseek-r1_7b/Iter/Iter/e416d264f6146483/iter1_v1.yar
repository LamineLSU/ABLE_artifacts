rule Bypass_Sample_Evolved
{
    meta:
        description = "Evasion bypass rule - specific call sequences followed by EAX tests"
        cape_options = "bp0=$pattern0+0,action0=skip,bp1=$pattern1+0,action1=skip,bp2=$pattern2+0,action2=skip,count=0"

    strings:
        $pattern0 = { 8B C4 F3 5E 76 FF FE FF FF FF 8B FC A9 0F E0 }
        $pattern1 = { 8B C4 F3 5E 76 FF FF FF FF FF 8B F8 D0 B2 }
        $pattern2 = { 8B C4 F3 5E 76 FF FF FF FF FF 8B FC A9 1C }

    condition:
        (any of the patterns match)
}