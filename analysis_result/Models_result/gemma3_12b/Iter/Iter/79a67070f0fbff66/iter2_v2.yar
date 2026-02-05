rule Bypass_Sample_Evolved
{
    meta:
        description = "Evasion bypass rule - evolved"
        cape_options = "bp0=0x0060B104+0,action0=skip,bp1=0x0060B124+0,action1=skip,bp2=0x0060B163+0,action2=skip,count=0"

    strings:
        $pattern0 = { FF 15 9C 50 61 00 }
        $pattern1 = { 8B 45 C4 83 C0 01 89 45 C4 }
        $pattern2 = { 83 3D 5C 42 61 00 00 }

    condition:
        any of them
}