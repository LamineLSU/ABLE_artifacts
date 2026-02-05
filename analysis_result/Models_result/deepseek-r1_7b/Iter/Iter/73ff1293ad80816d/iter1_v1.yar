rule Bypass_Sample_Evolved
{
    meta:
        description = "Evasion bypass using multiple specific instruction sequences"
        cape_options = "bp0=$pattern0+0,action0=skip,bp1=$pattern1+0,action1=skip,bp2=$pattern2+0,action2=skip,count=0"

    strings:
        $pattern0 = { E2 4A F5 85 C0 74 12 }
        $pattern1 = { 83 F8 01 07 45 FC 74 12 }
        $pattern2 = { E9 3B 5A 85 C0 74 1F }

    condition:
        any of them
}