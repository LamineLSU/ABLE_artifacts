rule Bypass_Sample_Evolved
{
    meta:
        description = "Evasion bypass targeting decision points"
        cape_options = "bp0=$pattern0+0,action0=skip,bp1=$pattern1+0,action1=skip,bp2=$pattern2+0,action2=skip,count=0"

    strings:
        $pattern0 = { 85 C0 74 12 6A 5B 5A 8B CE E8 25 05 00 00 }
        $pattern1 = { 83 F8 01 74 12 8B 8B 4D F8 5F }
        $pattern2 = { 89 9D F0 FE FF FF 01 31 61 9C 8B CE E8 74 FA FF FF }

    condition:
        (any of them)
}