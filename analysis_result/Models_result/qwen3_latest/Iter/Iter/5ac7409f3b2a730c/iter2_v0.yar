rule Bypass_Sample_Evolved
{
    meta:
        description = "Evasion bypass rule - evolved"
        cape_options = "bp0=$pattern0+0,action0=skip,bp1=$pattern1+0,action1=skip,bp2=$pattern2+0,action2=skip,count=0"

    strings:
        $pattern0 = { 85 C0 74 12 6A 5B 5A 8B CE } // test eax, je + push setup
        $pattern1 = { FF 15 ?? ?? ?? ?? } // ExitProcess call signature
        $pattern2 = { 53 6A 40 53 68 40 11 DD 00 } // push ebx + push 0x40 setup

    condition:
        any of them
}