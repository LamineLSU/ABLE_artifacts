rule Bypass_Sample
{
    meta:
        description = "Evasion bypass rule"
        cape_options = "bp0=$pattern0+0,action0=skip,bp1=$pattern1+0,action1=skip,bp2=$pattern2+0,action2=skip,count=0"

    strings:
        $pattern0 = { FF 75 08 E8 ?? ?? ?? ?? }  // Push ebp+08h + Call to ___crtCorExitProcess
        $pattern1 = { 59 FF 15 ?? ?? ?? ?? }     // Pop ecx + Call to ExitProcess
        $pattern2 = { 8B FF 55 8B EC FF 75 08 }  // Prologue: mov edi, push ebp, mov ebp, push ebp+08h

    condition:
        any of them
}