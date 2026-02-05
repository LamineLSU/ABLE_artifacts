rule Bypass_Sample
{
    meta:
        description = "Evasion bypass rule"
        cape_options = "bp0=$pattern0+0,action0=skip,bp1=$pattern1+0,action1=skip,bp2=$pattern2+0,action2=skip,count=0"

    strings:
        $pattern0 = { FF 75 08 E8 ?? ?? ?? ?? 59 }  // Push + Call (___crtCorExitProcess) + Pop
        $pattern1 = { 59 FF 15 ?? ?? ?? ?? }         // Pop + Call (ExitProcess)
        $pattern2 = { E8 ?? ?? ?? ?? 59 FF 15 ?? ?? ?? ?? }  // Call (___crtCorExitProcess) + Pop + Call (ExitProcess)

    condition:
        all of them
}