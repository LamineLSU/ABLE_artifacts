rule Bypass_Sample_Evolved
{
    meta:
        description = "Evasion bypass rule - evolved"
        cape_options = "bp0=$pattern0+0,action0=skip,bp1=$pattern1+0,action1=skip,bp2=$pattern2+0,action2=skip,count=0"

    strings:
        $pattern0 = { 85 C0 0F 84 ?? ?? ?? ?? }  // TEST EAX, EAX + JE (evasion check)
        $pattern1 = { FF 15 2C A1 0E 01 }         // CALL to ExitProcess (exit decision)
        $pattern2 = { A1 88 85 0E 01 85 C0 0F 84 ?? ?? ?? ?? }  // MOV + TEST EAX + JE (secondary check)

    condition:
        any of them
}