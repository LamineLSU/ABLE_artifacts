rule Bypass_Sample_Evolved
{
    meta:
        description = "Evasion bypass rule - evolved"
        cape_options = "bp0=$pattern0+0,action0=skip,bp1=$pattern1+0,action1=skip,bp2=$pattern2+0,action2=skip,count=0"

    strings:
        $pattern0 = { E8 ?? ?? ?? ?? 83 F8 01 74 ?? }  // call+cmp+je (evasion check)
        $pattern1 = { A8 01 75 ?? }                   // test al+ jne (evasion check)
        $pattern2 = { FF 75 08 FF 15 ?? ?? ?? ?? }     // push+call GetCurrentProcess (API check)

    condition:
        any of them
}