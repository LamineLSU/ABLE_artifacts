rule Bypass_Sample_Evolved
{
    meta:
        description = "Evasion bypass rule - evolved"
        cape_options = "bp0=$pattern0+0,action0=skip,bp1=$pattern1+0,action1=skip,bp2=$pattern2+0,action2=skip,count=0"

    strings:
        $pattern0 = { 8B 45 FC 83 F8 01 74 12 }  // test+je+mov (specific stack offset)
        $pattern1 = { E8 ?? ?? ?? ?? FF D0 }   // call GetTickCount
        $pattern2 = { 3D 00 10 00 00 0F 82 }    // cmp eax,imm32 + jb

    condition:
        any of them
}