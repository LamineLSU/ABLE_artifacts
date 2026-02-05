rule Bypass_Sample_Evolved
{
    meta:
        description = "Evasion bypass rule - evolved"
        cape_options = "bp0=$pattern0+0,action0=ignore,bp1=$pattern1+0,action1=ignore,bp2=$pattern2+0,action2=ignore,count=0"

    strings:
        $pattern0 = { 85 C0 74 12 ?? ?? ?? ?? }  // test eax, eax + je (first evasion check)
        $pattern1 = { 85 C0 0F 84 ?? ?? ?? ?? }   // test eax, eax + je (second evasion check)
        $pattern2 = { FF 15 ?? ?? ?? ?? ?? }      // ExitProcess call (6-byte pattern)

    condition:
        any of them
}