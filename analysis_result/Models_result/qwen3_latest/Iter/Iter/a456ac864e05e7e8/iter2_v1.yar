rule Bypass_Sample_Evolved
{
    meta:
        description = "Evasion bypass rule - evolved"
        cape_options = "bp0=$pattern0+0,action0=skip,bp1=$pattern1+0,action1=skip,bp2=$pattern2+0,action2=skip,count=0"

    strings:
        $pattern0 = { E8 ?? ?? ?? ?? }  // Call to ___crtCorExitProcess (evasion check)
        $pattern1 = { 55 8B EC }          // Prologue: push ebp, mov ebp, esp
        $pattern2 = { FF 15 ?? ?? ?? ?? } // Call to ExitProcess (exit decision)

    condition:
        any of them
}