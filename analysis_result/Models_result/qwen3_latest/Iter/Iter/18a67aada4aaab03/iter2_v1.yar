rule Bypass_Sample_Evolved
{
    meta:
        description = "Evasion bypass rule - evolved"
        cape_options = "bp0=$pattern0+0,action0=skip,bp1=$pattern1+0,action1=skip,bp2=$pattern2+0,action2=skip,count=0"

    strings:
        $pattern0 = { 83 F8 01 74 20 FF 75 08 }  // CMP EAX,01h + JE + PUSH
        $pattern1 = { E8 ?? ?? ?? ?? 83 F8 01 }  // CALL + CMP EAX,01h
        $pattern2 = { FF 15 ?? ?? ?? ?? 50 }      // CALL API + PUSH EAX

    condition:
        any of them
}