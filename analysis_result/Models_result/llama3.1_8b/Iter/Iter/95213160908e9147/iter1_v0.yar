rule Bypass_Sample_Evolved
{
    meta:
        description = "Evasion bypass rule - evolved"
        cape_options = "bp0=$pattern0+0,action0=skip,bp1=$pattern1+0,action1=skip,bp2=$pattern2+0,action2=skip,count=0"

    strings:
        $pattern0 = { 85 C0 0F 84 ?? ?? ?? ?? }  // test + je
        $pattern1 = { 83 F8 01 74 12 8B 4D F8 }  // cmp + je + mov (concrete bytes)
        $pattern2 = { 3D 00 10 00 00 0F 82 }  // cmp eax,imm32 + jb

    condition:
        any of them
}