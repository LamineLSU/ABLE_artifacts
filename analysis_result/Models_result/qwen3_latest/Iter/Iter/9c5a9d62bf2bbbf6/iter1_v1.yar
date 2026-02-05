rule Bypass_Sample_Evolved
{
    meta:
        description = "Evasion bypass rule - evolved"
        cape_options = "bp0=$pattern0+0,action0=skip,bp1=$pattern1+0,action1=skip,bp2=$pattern2+0,action2=skip,count=0"

    strings:
        $pattern0 = { 85 C0 74 12 8B 45 FC }  // TEST EAX, EAX + JE + MOV (control flow check)
        $pattern1 = { 0F 84 33 FD FF FF }  // Long conditional jump (evasion logic)
        $pattern2 = { FF 15 2C A1 08 00 }  // Direct ExitProcess API call (termination trigger)

    condition:
        any of them
}