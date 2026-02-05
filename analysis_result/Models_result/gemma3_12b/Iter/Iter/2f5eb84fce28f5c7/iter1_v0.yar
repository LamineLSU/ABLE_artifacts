rule Bypass_Sample_Evolved
{
    meta:
        description = "Evasion bypass rule - evolved"
        cape_options = "bp0=0x010D617A+0,action0=skip,bp1=0x010D61AB+0,action1=skip,bp2=0x010D61C5+0,action2=skip,count=0"

    strings:
        $pattern0 = { 85 C0 74 12 6A 5B }
        $pattern1 = { 8B 85 F0 FE FF FF 8D 8D F8 FE FF FF }
        $pattern2 = { 50 E8 E3 FA FF FF }

    condition:
        any of them
}