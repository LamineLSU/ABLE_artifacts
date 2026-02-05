rule Bypass_Sample_Evolved
{
    meta:
        description = "Evasion bypass rule - evolved"
        cape_options = "bp0=$pattern0+0,action0=skip,bp1=$pattern1+0,action1=skip,bp2=$pattern2+0,action2=skip,count=0"

    strings:
        $pattern0 = { 83 F8 01 74 20 8B 45 FC } // CMP EAX,01h + JE + MOV (evasion check)
        $pattern1 = { FF 15 ?? ?? ?? ?? } // CALL to API check (flexible offset)
        $pattern2 = { FF 15 B0 70 2D 01 } // CALL to ExitProcess decision point

    condition:
        any of them
}