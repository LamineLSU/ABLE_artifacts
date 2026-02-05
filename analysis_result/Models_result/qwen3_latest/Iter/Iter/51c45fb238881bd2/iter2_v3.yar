rule Bypass_Sample_Evolved
{
    meta:
        description = "Evasion bypass rule - evolved"
        cape_options = "bp0=$pattern0+0,action0=skip,bp1=$pattern1+0,action1=skip,bp2=$pattern2+0,action2=skip,count=0"

    strings:
        $pattern0 = { 6A 00 FF 96 B0 00 00 }  // Push-zero + call to evasion check
        $pattern1 = { FF 96 B0 00 00 00 }      // Direct call to evasion check
        $pattern2 = { 83 3D 00 10 49 00 00 }  // Memory comparison check

    condition:
        any of them
}