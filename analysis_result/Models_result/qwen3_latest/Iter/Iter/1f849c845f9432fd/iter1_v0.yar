rule Bypass_Sample_Evolved
{
    meta:
        description = "Evasion bypass rule - evolved"
        cape_options = "bp0=$pattern0+0,action0=skip,bp1=$pattern1+0,action1=skip,bp2=$pattern2+0,action2=skip,count=0"

    strings:
        $pattern0 = { E8 ?? ?? ?? ?? 85 C0 74 ?? } // CALL → TEST EAX → JE
        $pattern1 = { 85 C0 0F 84 ?? ?? ?? ?? }     // TEST EAX → JE (conditional check)
        $pattern2 = { FF 15 ?? ?? ?? ?? }           // ExitProcess call (termination point)

    condition:
        any of them
}