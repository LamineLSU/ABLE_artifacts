rule Bypass_Sample_Evolved
{
    meta:
        description = "Evasion bypass rule - evolved"
        cape_options = "bp0=$pattern0+0,action0=skip,bp1=$pattern1+0,action1=skip,bp2=$pattern2+0,action2=skip,count=0"

    strings:
        $pattern0 = { FF 15 ?? ?? ?? ?? 83 F8 11 74 ?? }  // VirtualAlloc call + EAX comparison + conditional jump
        $pattern1 = { 53 83 C4 0C 53 83 65 FC 00 FF 15 ?? ?? ?? ?? }  // Register manipulation + VirtualFree call
        $pattern2 = { 51 83 65 FC 00 6A 00 6A 40 68 ?? ?? ?? ?? FF 15 ?? ?? ?? ?? }  // Stack modification + VirtualAllocExNuma call

    condition:
        any of them
}