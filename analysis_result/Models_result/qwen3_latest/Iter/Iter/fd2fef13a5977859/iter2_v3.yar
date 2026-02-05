rule Bypass_Sample_Evolved
{
    meta:
        description = "Evasion bypass rule - evolved"
        cape_options = "bp0=$pattern0+0,action0=skip,bp1=$pattern1+0,action1=skip,bp2=$pattern2+0,action2=skip,count=0"

    strings:
        $pattern0 = { E8 ?? ?? ?? ?? }  // Initial call to evasion check function
        $pattern1 = { 83 F8 01 74 20 }     // CMP EAX, 01h + JE (evasion condition)
        $pattern2 = { 50 FF 15 ?? ?? ?? ?? }  // PUSH + CALL TerminateProcess (exit logic)

    condition:
        any of them
}