rule Bypass_Sample_Evolved
{
    meta:
        description = "Evasion bypass rule - specifically targets exit decisions"
        cape_options = "bp0=$pattern0+0,action0=skip,bp1=$pattern1+0,action1=skip,bp2=$pattern2+0,action2=skip,count=0"

    strings:
        $pattern0 = { 85 C0 74 12 6A 5B 5A 53 }
        $pattern1 = { 8D 95 F0 FE FF FF 00 22 61 90 8D 95 F0 FE FF FF 00 22 61 90 }
        $pattern2 = { 83 F8 01 74 12 8B 4D F8 }
    condition:
        (any of them)
}