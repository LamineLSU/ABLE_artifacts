rule Bypass_Sample_Evolved
{
    meta:
        description = "Evasion bypass rule - evolved"
        cape_options = "bp0=$pattern0+0,action0=skip,bp1=$pattern1+0,action1=skip,bp2=$pattern2+0,action2=skip,count=0"

    strings:
        $pattern0 = { 04 55 E8 43 1C 00 8B 45 FC }  // Specific call and conditional check
        $pattern1 = { 04 55 E8 2F 7E 00 8B 4D F8 }  // Another specific conditional call
        $pattern2 = { 04 55 E8 FF 96 00 8B 3D 00 }    // Additional conditional structure

    condition:
        any of them
}