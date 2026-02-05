rule Bypass_Sample_Evolved
{
    meta:
        description = "Evasion bypass rule - evolved"
        cape_options = "bp0=$pattern0+0,action0=skip,bp1=$pattern1+0,action1=skip,bp2=$pattern2+0,action2=skip,count=0"

    strings:
        $pattern0 = { 50 E8 ?? ?? ?? ?? }  // push eax + call (first evasion check)
        $pattern1 = { 51 FF D2 }            // push ecx + call edx (second evasion check)
        $pattern2 = { 52 FF D0 }            // push edx + call eax (ExitProcess trigger)

    condition:
        any of them
}