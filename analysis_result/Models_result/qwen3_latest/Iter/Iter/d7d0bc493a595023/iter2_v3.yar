rule Bypass_Sample_Evolved
{
    meta:
        description = "Evasion bypass rule - evolved"
        cape_options = "bp0=$pattern0+0,action0=skip,bp1=$pattern1+0,action1=skip,bp2=$pattern2+0,action2=skip,count=0"

    strings:
        $pattern0 = { E8 C1 FF FF FF }  // Call to ___crtCorExitProcess (evasion check)
        $pattern1 = { 55 8B EC }        // Stack setup (push ebp, mov ebp, esp)
        $pattern2 = { FF 75 08 }        // Push dword [ebp+08h] (stack manipulation)

    condition:
        any of them
}