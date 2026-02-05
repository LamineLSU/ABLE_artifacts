rule Bypass_Sample_Evolved
{
    meta:
        description = "Evasion bypass rule - evolved with multiple strategies"
        cape_options = "bp0=$pattern0+0,action0=skip,bp1=$pattern1+0,action1=skip,bp2=$pattern2+0,action2=skip,count=0"

    strings:
        $pattern0 = { 83 EC 48 00 00 00 00 00 }  // TEST JAE at offset 0
        $pattern1 = { 83 65 E4 00 00 00 00 00 }  // JE/JNE before exit decision
        $pattern2 = { F8 00 4F 00 00 00 00 00 }  // RDPSC for evasion tech
    condition:
        any of them
}