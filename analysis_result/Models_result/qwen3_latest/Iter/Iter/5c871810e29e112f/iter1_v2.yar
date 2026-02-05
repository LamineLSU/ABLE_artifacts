rule Bypass_Sample_Evolved
{
    meta:
        description = "Evasion bypass rule - evolved"
        cape_options = "bp0=$pattern0+0,action0=skip,bp1=$pattern1+0,action1=skip,bp2=$pattern2+0,action2=skip,count=0"

    strings:
        $pattern0 = { 85 C0 74 12 6A 5B }  // Test + je + push (evasion check)
        $pattern1 = { 0F 84 ?? ?? ?? ?? }  // je to ExitProcess (decision point)
        $pattern2 = { FF 15 ?? ?? ?? ?? }  // ExitProcess call (termination signal)

    condition:
        any of them
}