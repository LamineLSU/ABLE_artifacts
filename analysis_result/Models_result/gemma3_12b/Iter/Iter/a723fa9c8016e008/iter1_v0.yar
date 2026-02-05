rule Bypass_Sample_Evolved
{
    meta:
        description = "Evasion bypass rule - evolved"
        cape_options = "bp0=0x0002617A+0,action0=skip,bp1=0x00026196+0,action1=skip,bp2=0x000261C6+0,action2=skip,count=0"

    strings:
        $pattern0 = { 85 C0 74 12 6A 5B }
        $pattern1 = { 89 9D F0 FE FF FF 8B CE }
        $pattern2 = { 50 E8 E3 FA FF FF }

    condition:
        any of them
}