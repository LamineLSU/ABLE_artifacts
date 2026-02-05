rule Bypass_Sample_Evolved
{
    meta:
        description = "Evasion bypass rule - evolved"
        cape_options = "bp0=$pattern0+0,action0=skip,bp1=$pattern1+0,action1=skip,bp2=$pattern2+0,action2=skip,count=0"

    strings:
        $pattern0 = { E8 FD AF FF ?? 85 C0 74 16 }  // First evasion check (call + test + je)
        $pattern1 = { E8 70 84 FF ?? 85 C0 74 08 }  // Second evasion check (call + test + je)
        $pattern2 = { FF 15 0C F2 47 00 }          // ExitProcess call (termination decision point)

    condition:
        any of them
}