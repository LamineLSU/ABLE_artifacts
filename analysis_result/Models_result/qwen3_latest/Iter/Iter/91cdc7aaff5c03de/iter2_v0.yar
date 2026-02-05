rule Bypass_Sample_Evolved
{
    meta:
        description = "Evasion bypass rule - evolved"
        cape_options = "bp0=$pattern0+0,action0=skip,bp1=$pattern1+0,action1=skip,bp2=$pattern2+0,action2=skip,count=0"

    strings:
        $pattern0 = { 80 3D ?? ?? ?? ?? 00 0F 85 ?? ?? ?? ?? } // cmp + jne sequence
        $pattern1 = { E8 2A 00 00 00 83 7C 24 10 01 } // call DeleteFileW + test instruction
        $pattern2 = { 0F 84 8C 00 00 00 } // jz instruction

    condition:
        any of them
}