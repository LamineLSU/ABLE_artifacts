rule Bypass_Sample_Evolved
{
    meta:
        description = "Evasion bypass rule - evolved"
        cape_options = "bp0=$pattern0+0,action0=skip,bp1=$pattern1+0,action1=skip,bp2=$pattern2+0,action2=skip,count=0"

    strings:
        $pattern0 = { E8 89 E0 FF FF 85 C0 74 0E }  // Call -> Test EAX -> JE (evasion check)
        $pattern1 = { E8 E0 A2 FF FF 85 C0 74 0E }  // Another Call -> Test EAX -> JE (evasion check)
        $pattern2 = { FF 15 14 28 43 00 }            // ExitProcess call (exit decision)

    condition:
        any of them
}