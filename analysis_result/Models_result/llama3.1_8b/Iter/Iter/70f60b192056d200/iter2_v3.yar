rule Bypass_Sample_Evolved
{
    meta:
        description = "Evasion bypass rule - evolved"
        cape_options = "bp0=$pattern0+0,action0=skip,bp1=$pattern1+0,action1=skip,bp2=$pattern2+0,action2=skip,count=0"

    strings:
        $pattern0 = { 85 C0 0F 84 ?? ?? ?? ?? } // test+je+mov (specific stack offset)
        $pattern1 = { 83 F8 01 74 12 8B 4D F8 } // cmp+je+mov (concrete bytes, very specific)
        $pattern2 = { E8 F7 25 00 00 FF 15 A0 F1 42 00 } // call check function before exit

    condition:
        any of them
}