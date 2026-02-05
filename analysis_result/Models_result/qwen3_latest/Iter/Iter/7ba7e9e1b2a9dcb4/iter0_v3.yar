rule Bypass_Sample
{
    meta:
        description = "Evasion bypass rule"
        cape_options = "bp0=$pattern0+0,action0=skip,bp1=$pattern1+0,action1=skip,bp2=$pattern2+0,action2=skip,count=0"

    strings:
        $pattern0 = { 85 C0 74 12 ?? ?? ?? ?? }  // Test EAX + JE (first sandbox check)
        $pattern1 = { 85 C0 0F 84 33 FD FF FF }  // Test EAX + JE (second sandbox check)
        $pattern2 = { 53 FF 15 ?? ?? ?? ?? }     // Push EBX + CALL ExitProcess (final exit)

    condition:
        any of them
}