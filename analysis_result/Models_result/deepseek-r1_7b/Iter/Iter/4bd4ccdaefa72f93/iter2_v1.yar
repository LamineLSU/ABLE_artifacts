rule Bypass_Sample_Evolved
{
    meta:
        description = "Evasion bypass rule - evolved"
        cape_options = "bp0=$pattern0+0,action0=skip,bp1=$pattern1+0,action1=skip,bp2=$pattern2+0,action2=skip,count=0"

    strings:
        $pattern0 = { 48 8D 4C 24 60 EA CD 60 }
        $pattern1 = { 83 F8 01 74 12 8B 4D F8 } // Conditional comparison
        $pattern2 = { 3D 00 10 00 00 0F 82 } // Timing check example

    condition:
        any of them
}