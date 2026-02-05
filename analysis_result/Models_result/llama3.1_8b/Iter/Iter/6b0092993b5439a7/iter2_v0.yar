rule Bypass_Sample_Evolved
{
    meta:
        description = "Evasion bypass rule - evolved"
        cape_options = "bp0=$pattern1+0,action0=skip,bp1=$pattern2+0,action1=skip,count=0"

    strings:
        $pattern1 = { 85 C0 0F 84 ?? ?? ?? ?? } // test+je
        $pattern2 = { 83 F8 01 74 12 8B 4D F8 } // cmp+je+mov (concrete bytes)

    condition:
        any of them
}