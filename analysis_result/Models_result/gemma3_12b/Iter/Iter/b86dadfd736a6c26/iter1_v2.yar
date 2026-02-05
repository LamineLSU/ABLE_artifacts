rule Bypass_Sample_Evolved
{
    meta:
        description = "Evasion bypass rule - evolved"
        cape_options = "bp0=$pattern0+0,action0=skip,bp1=$pattern1+0,action1=skip,bp2=$pattern2+0,action2=skip,count=0"

    strings:
        $pattern0 = { 83 FA 05 75 02 EB 02 }
        $pattern1 = { EB E9 83 FA 05 75 02 }
        $pattern2 = { 6A 00 5A 8B CE E8 4F FF FF FF 85 C0 }

    condition:
        any of them
}