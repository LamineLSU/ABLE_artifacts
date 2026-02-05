rule Bypass_Sample
{
    meta:
        description = "Evasion bypass rule"
        cape_options = "bp0=$pattern0+0,action0=skip,bp1=$pattern1+0,action1=skip,bp2=$pattern2+0,action2=skip,count=0"

    strings:
        $pattern0 = { 85 C0 75 07 FF 15 ?? ?? ?? ?? }  // Test EAX + JNE + ExitProcess call
        $pattern1 = { 50 FF 15 ?? ?? ?? ?? }           // Push EAX + VirtualAllocExNuma call
        $pattern2 = { 56 57 FF 15 ?? ?? ?? ?? }        // Push ESI/EDI + VirtualFree call

    condition:
        any of them
}