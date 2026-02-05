rule Bypass_Sample_Evolved
{
    meta:
        description = "Evasion bypass rule - evolved"
        cape_options = "bp0=$pattern0+0,action0=skip,bp1=$pattern1+0,action1=skip,bp2=$pattern2+0,action2=skip,count=0"

    strings:
        $pattern0 = { 55 8B EC FF 75 08 }  // CRT stack setup (push ebp, mov ebp, esp, push [ebp+08h])
        $pattern1 = { FF 15 ?? ?? ?? ?? }  // ExitProcess call with variable address
        $pattern2 = { E8 ?? ?? ?? ?? 59 }  // ___crtCorExitProcess call followed by pop ecx

    condition:
        any of them
}