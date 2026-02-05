rule Bypass_Sample
{
    meta:
        description = "Evasion bypass rule"
        cape_options = "bp0=$pattern0+0,action0=skip,bp1=$pattern1+0,action1=skip,bp2=$pattern2+0,action2=skip,count=0"

    strings:
        $pattern0 = { 85 C0 0F 84 ?? ?? ?? ?? }  // Test EAX + JZ (First evasion check)
        $pattern1 = { 53 FF 15 ?? ?? ?? ?? }     // Push EBX + CALL ExitProcess (Direct exit trigger)
        $pattern2 = { 85 C0 FF 15 ?? ?? ?? ?? }  // Test EAX + CALL CloseHandle (Second evasion check)

    condition:
        any of them
}