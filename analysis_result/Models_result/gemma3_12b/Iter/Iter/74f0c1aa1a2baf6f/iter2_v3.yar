rule Bypass_Sample_Evolved
{
    meta:
        description = "Evasion bypass rule - evolved"
        cape_options = "bp0=$pattern0+0,action0=skip,bp1=$pattern1+0,action1=skip,bp2=$pattern2+0,action2=skip,count=0"

    strings:
        $pattern0 = { 83 65 E8 00 8D 45 BC }
        $pattern1 = { 53 68 64 48 D1 00 }
        $pattern2 = { 8A D9 FF 15 20 41 D1 00 }

    condition:
        any of them
}