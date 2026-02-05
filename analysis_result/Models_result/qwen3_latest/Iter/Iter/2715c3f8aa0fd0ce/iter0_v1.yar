rule Bypass_Sample
{
    meta:
        description = "Evasion bypass rule"
        cape_options = "bp0=$pattern0+0,action0=skip,bp1=$pattern1+0,action1=skip,bp2=$pattern2+0,action2=skip,count=0"

    strings:
        $pattern0 = { 83 F8 01 74 ?? 8B 40 68 C1 E8 08 A8 01 75 ?? }  // CMP + JE + MOV + SHR + TEST + JNE
        $pattern1 = { FF 75 08 FF 15 ?? ?? ?? ?? ?? 50 FF 15 ?? ?? ?? ?? }  // PUSH + CALL + PUSH + CALL
        $pattern2 = { FF 75 08 E8 ?? ?? ?? ?? FF 15 ?? ?? ?? ?? }  // PUSH + CALL + CALL ExitProcess

    condition:
        any of them
}