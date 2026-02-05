rule Bypass_Sample_Evolved
{
    meta:
        description = "Evasion bypass rule - evolved"
        cape_options = "bp0=$pattern0+0,action0=skip,bp1=$pattern1+0,action1=skip,bp2=$pattern2+0,action2=skip,count=0"

    strings:
        $pattern0 = { 85 C0 0F 84 33 FD FF FF 8B 45 FC }
        $pattern1 = { 8D 95 F0 FE FF FF 89 9D F0 FE FF FF }
        $pattern2 = { E8 74 FA FF FF 85 C0 0F 84 33 FD FF FF }

    condition:
        any of them
}