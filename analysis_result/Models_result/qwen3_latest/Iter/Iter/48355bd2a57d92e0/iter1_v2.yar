rule Bypass_Sample_Evolved
{
    meta:
        description = "Evasion bypass rule - evolved"
        cape_options = "bp0=$pattern0+0,action0=skip,bp1=$pattern1+0,action1=skip,bp2=$pattern2+0,action2=skip,count=0"

    strings:
        $pattern0 = { 85 FF 74 39 8B 45 C4 }  // TEST EDI, JE, then MOV EAX
        $pattern1 = { FF 15 ?? ?? ?? ?? }     // Call to ExitProcess (API)
        $pattern2 = { 53 E8 ?? ?? ?? ?? }     // PUSH EBX + CALL (offset varies)

    condition:
        any of them
}