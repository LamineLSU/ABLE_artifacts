rule Bypass_Sample_Evolved
{
    meta:
        description = "Evasion bypass rule - evolved"
        cape_options = "bp0=$pattern1+0,action0=skip,bp2=$pattern3+0,action2=skip"

    strings:
        $pattern1 = { 85 C0 0F 84 ?? ?? ?? ?? }   // test+je (specific sequence)
        $pattern2 = { 83 F8 01 74 12 8B 4D F8 }   // cmp+je+mov (concrete bytes, specific)
        $pattern3 = { FF 15 2C ?? ?? ?? ?? }       // call dword ptr [??]

    condition:
        any of them
}