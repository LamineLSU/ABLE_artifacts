rule Bypass_Sample_Evolved
{
    meta:
        description = "Evasion bypass rule - evolved"
        cape_options = "bp0=$pattern0+0,action0=skip,bp1=$pattern1+0,action1=skip,bp2=$pattern2+0,action2=skip,count=0"

    strings:
        $pattern0 = E8 ?? ?? ?? ?? 85 C0 74 ??  // CALL → TEST EAX → JE (evasion check)
        $pattern1 = FF15 ?? ?? ?? ??             // ExitProcess call (target exit decision)
        $pattern2 = 50 FF15 ?? ?? ?? ??          // PUSH EAX + CALL (unique sequence)

    condition:
        any of them
}