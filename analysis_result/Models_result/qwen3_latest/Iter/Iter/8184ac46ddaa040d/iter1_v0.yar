rule Bypass_Sample_Evolved
{
    meta:
        description = "Evasion bypass rule - evolved"
        cape_options = "bp0=$pattern0+0,action0=skip,bp1=$pattern1+0,action1=skip,bp2=$pattern2+0,action2=skip,count=0"

    strings:
        $pattern0 = { E8 ?? ?? ?? ?? 85 C0 0F 84 ?? ?? ?? ?? }  // CALL → TEST EAX → JE (evasion check)
        $pattern1 = { 50 FF 15 ?? ?? ?? ?? }                     // PUSH + CALL (pre-exit decision)
        $pattern2 = { A1 ?? ?? ?? ?? 85 C0 0F 84 ?? ?? ?? ?? }   // MOV + TEST EAX → JE (exit logic)

    condition:
        any of them
}