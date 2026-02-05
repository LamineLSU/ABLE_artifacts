rule Bypass_Sample_Evolved
{
    meta:
        description = "Evasion bypass rule - evolved"
        cape_options = "bp0=$pattern0+0,action0=skip,bp1=$pattern1+0,action1=skip,bp2=$pattern2+0,action2=skip,count=0"

    strings:
        $pattern0 = { 80 3D 86 0A 46 00 } // cmp byte ptr [00460A86h], 00
        $pattern1 = { E8 16 A5 FF FF E9 EB 00 00 00 } // call + jmp sequence
        $pattern2 = { 38 1D 97 0A 46 00 75 F0 } // cmp byte ptr [00460A97h], bl + jne

    condition:
        any of them
}