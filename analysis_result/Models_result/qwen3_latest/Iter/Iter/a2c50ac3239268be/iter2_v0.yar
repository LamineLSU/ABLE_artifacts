rule Bypass_Sample_Evolved
{
    meta:
        description = "Evasion bypass rule - evolved"
        cape_options = "bp0=$pattern0+0,action0=skip,bp1=$pattern1+0,action1=skip,bp2=$pattern2+0,action2=skip,count=0"

    strings:
        $pattern0 = { 83 3D 00 C0 4A 00 00 75 0E }  // cmp dword + jne
        $pattern1 = { E8 F7 FB FF FF 80 7B 28 01 }  // call + cmp byte
        $pattern2 = { 85 FF 74 1C 8B 4D F8 }         // test edi + je + mov

    condition:
        any of them
}