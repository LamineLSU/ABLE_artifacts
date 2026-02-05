rule Bypass_Sample_Evolved
{
    meta:
        description = "Evasion bypass rule - evolved"
        cape_options = "bp0=$pattern0+0,action0=skip,bp1=$pattern1+0,action1=skip,bp2=$pattern2+0,action2=skip,count=0"

    strings:
        $pattern0 = { E8 ?? ?? ?? ?? 85 C0 0F 84 ?? ?? ?? ?? }  // CALL + TEST EAX + JE
        $pattern1 = { B9 42 8C 0A 01 50 E8 ?? ?? ?? ?? }         // MOV ECX + PUSH + CALL
        $pattern2 = { 8B 4D F8 FF 15 ?? ?? ?? ?? }               // MOV EAX + CALL (ExitProcess)

    condition:
        any of them
}