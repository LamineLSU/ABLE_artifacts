rule Bypass_Sample_Evolved
{
    meta:
        description = "Evasion bypass rule - evolved"
        cape_options = "bp0=$pattern0+0,action0=skip,bp1=$pattern1+0,action1=skip,bp2=$pattern2+0,action2=skip,count=0"

    strings:
        $pattern0 = { 85 C0 0F 84 ?? ?? ?? ?? }  // test eax, eax + je (zero-check)
        $pattern1 = { FF 15 ?? ?? ?? ?? }         // call to ExitProcess (API check)
        $pattern2 = { BA 04 01 00 00 E8 ?? ?? ?? ?? }  // mov + call (logic flow)

    condition:
        any of them
}