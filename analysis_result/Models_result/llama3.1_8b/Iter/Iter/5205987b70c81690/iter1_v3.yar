rule Bypass_Sample_Evolved
{
    meta:
        description = "Evasion bypass rule - evolved"
        cape_options = "bp0=$pattern0+0,action0=skip,bp1=$pattern1+0,action1=skip,bp2=$pattern2+0,action2=skip,count=0"

    strings:
        $pattern0 = { 85 C0 0F 84 ?? ?? ?? ?? }  // test+jmp (conditional check)
        $pattern1 = { DC 8B 45 FC 83 F8 01 }  // timing check and load offset
        $pattern2 = { CD E8 C8 FF FF FF }  // vm detect and jump

    condition:
        any of them
}