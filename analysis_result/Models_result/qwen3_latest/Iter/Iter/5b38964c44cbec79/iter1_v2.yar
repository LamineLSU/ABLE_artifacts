rule Bypass_Sample_Evolved
{
    meta:
        description = "Evasion bypass rule - evolved"
        cape_options = "bp0=$pattern0+0,action0=skip,bp1=$pattern1+0,action1=skip,bp2=$pattern2+0,action2=skip,count=0"

    strings:
        $pattern0 = { E8 ?? ?? ?? ?? 85 C0 74 12 }  // CALL + TEST EAX + JE (evasion check)
        $pattern1 = { FF 15 ?? ?? ?? ?? }             // CALL to ExitProcess (exit decision)
        $pattern2 = { E8 ?? ?? ?? ?? 8B 4D FC }      // CALL + MOV (additional evasion logic)

    condition:
        any of them
}