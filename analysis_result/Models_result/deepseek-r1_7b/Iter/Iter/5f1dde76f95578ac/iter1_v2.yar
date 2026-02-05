rule Bypass_Sample_Evolved
{
    meta:
        description = "Evasion bypass rule - evolved"
        cape_options = "bp0=$pattern0+0,action0=skip,bp1=$pattern1+0,action1=skip,bp2=$pattern2+0,action2=skip,count=0"

    strings:
        $pattern0 = { 85 C0 74 12 6A 5B 5A 8B CE 0F 84 33 FD FF FF }
        $pattern1 = { 5A 0F 84 33 FD FF FF 74 12 8D 95 F0 FE FF FF 0F 84 33 FD FF FF }
        $pattern2 = { 6A 40 05 03 C3 0B A0 01 01 03 C1 05 }

    condition:
        any of them
}