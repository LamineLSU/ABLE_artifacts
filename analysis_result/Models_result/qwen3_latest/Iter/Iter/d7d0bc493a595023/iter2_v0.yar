rule Bypass_Sample_Evolved
{
    meta:
        description = "Evasion bypass rule - evolved"
        cape_options = "bp0=$pattern0+0,action0=skip,bp1=$pattern1+0,action1=skip,bp2=$pattern2+0,action2=skip,count=0"

    strings:
        $pattern0 = { E8 C1 FF FF FF 59 }  // Call to ___crtCorExitProcess followed by pop ecx
        $pattern1 = { FF 75 03 FF 15 68 F3 20 00 }  // Push ebp+03h followed by call ExitProcess
        $pattern2 = { 55 8B EC FF 75 08 }  // Stack setup (push ebp, mov ebp, push ebp+08h)

    condition:
        all of them
}