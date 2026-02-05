rule Bypass_Sample
{
    meta:
        description = "Evasion bypass rule"
        cape_options = "bp0=$pattern0+0,action0=skip,bp1=$pattern1+0,action1=skip,bp2=$pattern2+0,action2=skip,count=0"

    strings:
        $pattern0 = { 85 C0 0F 84 ?? ?? ?? ?? FF 15 ?? ?? ?? ?? }  // TEST EAX + JE + CALL (TRACE //1)
        $pattern1 = { E8 C8 FF FF 59 FF 15 ?? ?? ?? ?? }             // CALL + POP + CALL (TRACE //3)
        $pattern2 = { 83 F8 01 75 10 FF 15 ?? ?? ?? ?? }            // CMP EAX + JNE + CALL (TRACE //5)

    condition:
        any of them
}