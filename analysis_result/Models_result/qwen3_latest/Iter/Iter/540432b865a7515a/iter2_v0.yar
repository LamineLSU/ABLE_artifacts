rule Bypass_Sample
{
    meta:
        description = "Evasion bypass rule"
        cape_options = "bp0=$pattern0+0,action0=skip,bp1=$pattern1+0,action1=skip,bp2=$pattern2+0,action2=skip,count=0"

    strings:
        $pattern0 = { 85 C0 74 07 E8 ?? ?? ?? ?? }  // Test EAX + JE + CALL (TRACE //1)
        $pattern1 = { 50 FF 15 ?? ?? ?? ?? }        // PUSH + CALL (TRACE //1)
        $pattern2 = { FF 75 08 E8 ?? ?? ?? ?? }     // PUSH [EBP+08h] + CALL (TRACE //3)

    condition:
        any of them
}