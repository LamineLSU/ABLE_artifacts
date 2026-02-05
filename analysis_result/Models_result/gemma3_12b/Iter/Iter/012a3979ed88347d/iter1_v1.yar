rule Bypass_Sample_Evolved
{
    meta:
        description = "Evasion bypass rule - evolved"
        cape_options = "bp0=0x00E7617A+0,action0=skip,bp1=0x00E76190+0,action1=skip,bp2=0x00E761A5+0,action2=skip,count=0"

    strings:
        $pattern0 = { 85 C0 74 12 6A 5B }
        $pattern1 = { 8D 95 F0 FE FF FF 89 9D F0 FE FF FF }
        $pattern2 = { 85 C0 0F 84 33 FD FF FF }

    condition:
        any of them
}