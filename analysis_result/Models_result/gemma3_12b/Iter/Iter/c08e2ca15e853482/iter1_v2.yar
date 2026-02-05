rule Bypass_Sample_Evolved
{
    meta:
        description = "Evasion bypass rule - evolved"
        cape_options = "bp0=$pattern0+0,action0=skip,bp1=$pattern1+0,action1=skip,bp2=$pattern2+0,action2=skip,count=0"

    strings:
        $pattern0 = { 85 C9 74 05 8B 45 FC }
        $pattern1 = { 83 F8 11 74 05 8B 4D F8 }
        $pattern2 = { 74 2B 90 8A C0 68 C0 9E E6 05 }

    condition:
        any of them
}