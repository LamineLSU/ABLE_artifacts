rule Bypass_Sample_Evolved
{
    meta:
        description = "Evasion bypass rule - evolved"
        cape_options = "bp0=$pattern0+0,action0=skip,bp1=$pattern1+0,action1=skip,bp2=$pattern2+0,action2=skip,count=0"

    strings:
        $pattern0 = { 8B 5D C8 8B 4D C4 8B 7D C0 6A FF 6A 01 51 57 FF 15 50 A0 20 00 }
        $pattern1 = { 83 F8 01 74 12 8B 4D F8 }
        $pattern2 = { 3D 00 10 00 00 0F 82 }

    condition:
        any of them
}