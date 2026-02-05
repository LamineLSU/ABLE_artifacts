rule Bypass_Sample_Evolved
{
    meta:
        description = "Evasion bypass rule - evolved"
        cape_options = "bp0=$pattern0+0,action0=skip,bp1=$pattern1+0,action1=skip,bp2=$pattern2+0,action2=skip,count=0"

    strings:
        $pattern0 = { 8B 5D C8 8B 4D C4 8B 7D C0 6A FF 6A 01 51 57 FF 15 50 A0 20 00 }
        $pattern1 = { 83 3E 00 74 14 FF 36 6A 00 FF 15 44 A0 20 00 50 FF 15 40 A0 20 00 }
        $pattern2 = { 8B 45 C4 8B F3 2B C3 89 45 C0 8B D8 FF 15 84 A0 20 00 }

    condition:
        any of them
}