rule Bypass_Sample
{
    meta:
        description = "Evasion bypass rule"
        cape_options = "bp0=$pattern0+0,action0=skip,bp1=$pattern1+0,action1=skip,bp2=$pattern2+0,action2=skip,count=0"

    strings:
        $pattern0 = { 85 C0 74 12 8B CE E8 ?? ?? ?? ?? }  // Test EAX + JE + MOV + CALL (11 bytes)
        $pattern1 = { 50 FF 15 ?? ?? ?? ?? }                // PUSH + CALL with offset wildcards (6 bytes)
        $pattern2 = { FF 75 08 FF 15 ?? ?? ?? ?? }          // PUSH dword + CALL with offset wildcards (8 bytes)

    condition:
        any of them
}