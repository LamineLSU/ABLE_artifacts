rule Bypass_Sample_Evolved
{
    meta:
        description = "Evasion bypass rule - evolved"
        cape_options = "bp0=$pattern0+0,action0=skip,bp1=$pattern1+0,action1=skip,bp2=$pattern2+0,action2=skip,count=0"

    strings:
        $pattern0 = { 8B F0 85 C9 74 12 8B 45 FC }  // test eax, ecx + je + mov
        $pattern1 = { 83 F8 01 74 12 8B 4D F8 }  // cmp + je + mov (concrete bytes)
        $pattern2 = { FF D0 89 C9 75 05 E8 C3 }  // call + test eax, ecx + jne + jmp

    condition:
        any of them
}