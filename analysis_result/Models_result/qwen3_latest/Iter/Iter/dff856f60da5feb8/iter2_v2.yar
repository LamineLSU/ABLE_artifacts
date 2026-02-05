rule Bypass_Sample_Evolved
{
    meta:
        description = "Evasion bypass rule - evolved"
        cape_options = "bp0=$pattern0+0,action0=skip,bp1=$pattern1+0,action1=skip,bp2=$pattern2+0,action2=skip,count=0"

    strings:
        $pattern0 = { E8 25 05 00 00 85 C0 }
        $pattern1 = { E8 74 FA FF FF 85 C0 }
        $pattern2 = { FF 15 2C A1 39 01 53 }

    condition:
        any of them
}