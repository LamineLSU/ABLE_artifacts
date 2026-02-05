rule Bypass_Sample_Evolved
{
    meta:
        description = "Evasion bypass rule - evolved"
        cape_options = "bp0=$pattern0+0,action0=skip,bp1=$pattern1+0,action1=skip,bp2=$pattern2+0,action2=skip,count=0"

    strings:
        $pattern0 = { E8 ?? ?? ?? ?? 84 C0 74 2A } // Call -> Test al, al -> je
        $pattern1 = { 3D 00 10 00 00 0F 82 ?? ?? ?? ?? } // cmp eax, 0x00100000 + jl
        $pattern2 = { FF 15 ?? ?? ?? ?? } // ExitProcess call

    condition:
        any of them
}