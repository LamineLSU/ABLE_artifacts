rule Bypass_Sample_Evolved
{
    meta:
        description = "Detects evasion logic or control flow manipulation through stack setup and function calls"
        cape_options = "bp0=$pattern0+0,action0=skip,bp1=$pattern1+0,action1=skip,bp2=$pattern2+0,action2=skip,count=0"

    strings:
        $pattern0 = { E8 ?? ?? ?? ?? 59 }  // Call to _crtCorExitProcess followed by POP ECX
        $pattern1 = { 55 8B EC FF 75 08 }   // Stack frame setup + push [ebp+08h]
        $pattern2 = { FF 15 ?? ?? ?? ?? }  // Call to ExitProcess (relative address)

    condition:
        any of them
}