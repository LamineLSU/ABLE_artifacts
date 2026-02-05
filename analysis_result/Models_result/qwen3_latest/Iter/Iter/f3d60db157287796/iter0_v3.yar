rule Bypass_Sample
{
    meta:
        description = "Evasion bypass rule"
        cape_options = "bp0=$pattern0+0,action0=skip,bp1=$pattern1+0,action1=skip,bp2=$pattern2+0,action2=skip,count=0"

    strings:
        $pattern0 = { 85 C0 0F 84 ?? ?? ?? ?? 8B 45 ?? }  // Test EAX + JZ + MOV
        $pattern1 = { A8 01 75 10 8B 40 68 C1 E8 08 }      // Test AL + JNE + MOV + SHR
        $pattern2 = { FF 15 ?? ?? ?? ?? 59 FF 75 08 FF 15 ?? ?? ?? ?? }  // CALL + POP + PUSH + CALL

    condition:
        any of them
}