rule Bypass_Sample_Evolved
{
    meta:
        description = "Evasion bypass rule - evolved"
        cape_options = "bp0=$pattern0+0,action0=skip,bp1=$pattern1+0,action1=skip,bp2=$pattern2+0,action2=skip,count=0"

    strings:
        $pattern0 = { 83 F8 ?? 74 ?? 8B 4D ?? } // cmp + je + mov (concrete bytes)
        $pattern1 = { 3D ?? ?? ?? 00 0F 82 ?? ?? } // cmp eax,imm32 + jb (concrete comparison value)
        $pattern2 = { FF 15 ?? ?? ?? ?? ?? ?? ?? } // call dword ptr [addr] (exit decision point)

    condition:
        any of them
}