rule Bypass_Sample_Evolved
{
    meta:
        description = "Evasion bypass rule - evolved"
        cape_options = "bp0=$pattern0+0,action0=skip,bp1=$pattern1+0,action1=skip,bp2=$pattern2+0,action2=skip,count=0"

    strings:
        $pattern0 = { E8 C8 FF FF FF 59 }  // Call to ___crtCorExitProcess followed by pop ecx
        $pattern1 = { 55 8B EC FF 75 08 }      // Function prologue + push [ebp+8h]
        $pattern2 = { 59 FF 75 08 FF 15 AC B0 41 00 }  // Pop ecx + push [ebp+8h] + call ExitProcess

    condition:
        all of them
}