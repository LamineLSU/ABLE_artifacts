rule Bypass_Sample_Evolved
{
    meta:
        description = "Evasion bypass rule - evolved"
        cape_options = "bp0=$pattern0+0,action0=skip,bp1=$pattern1+0,action1=skip,bp2=$pattern2+0,action2=skip,count=0"

    strings:
        $pattern0 = { 85 C0 74 ?? 6A 5B }  // Test EAX, JE, Push
        $pattern1 = { 50 FF 15 ?? ?? ?? ?? 53 }  // Push, Call ExitProcess, Push
        $pattern2 = { 85 C0 0F 84 ?? ?? ?? ?? }  // Test EAX, JE with 32-bit offset

    condition:
        any of them
}