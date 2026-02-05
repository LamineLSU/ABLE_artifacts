rule Bypass_Sample_Evolved
{
    meta:
        description = "Evasion bypass rule - evolved"
        cape_options = "bp0=$pattern0+0,action0=skip,bp1=$pattern1+0,action1=skip,bp2=$pattern2+0,action2=skip,count=0"

    strings:
        $pattern0 = { 75 0E 83 3D 00 C0 4A 00 00 75 0E }
        $pattern1 = { 33 C0 89 43 0C E8 F7 FB FF FF 80 7B 28 01 }
        $pattern2 = { 85 FF 74 1C 8B 7B 10 }

    condition:
        any of them
}