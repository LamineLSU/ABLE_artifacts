rule Bypass_Sample_Evolved
{
    meta:
        description = "Evasion bypass rule - evolved"
        cape_options = "bp0=$pattern0+0,action0=skip,bp1=$pattern1+0,action1=skip,bp2=$pattern2+0,action2=skip,count=0"

    strings:
        $pattern0 = { 85 C0 74 12 6A 5B 5A } // test eax, eax + je + push 0x5B + pop edx
        $pattern1 = { FF 15 ?? ?? ?? ?? } // call to ExitProcess (address varies)
        $pattern2 = { 85 C0 0F 84 ?? ?? ?? ?? } // test eax, eax + je with variable offset

    condition:
        any of them
}