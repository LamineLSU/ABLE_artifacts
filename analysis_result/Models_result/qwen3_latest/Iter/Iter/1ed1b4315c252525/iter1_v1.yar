rule Bypass_Sample_Evolved
{
    meta:
        description = "Evasion bypass rule - evolved"
        cape_options = "bp0=$pattern0+0,action0=skip,bp1=$pattern1+0,action1=skip,bp2=$pattern2+0,action2=skip,count=0"

    strings:
        $pattern0 = { E8 ?? ?? ?? ?? 59 }  // Call to ___crtCorExitProcess@LIBCMT.LIB followed by POP ECX
        $pattern1 = { FF 15 ?? ?? ?? ?? }  // Call to ExitProcess@KERNEL32.DLL (displacement)
        $pattern2 = { FF 75 08 FF 15 ?? ?? ?? ?? }  // PUSH [ebp+08h] + call to ExitProcess

    condition:
        any of them
}