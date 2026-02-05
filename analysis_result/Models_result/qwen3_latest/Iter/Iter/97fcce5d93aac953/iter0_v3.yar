rule Bypass_Sample
{
    meta:
        description = "Evasion bypass rule"
        cape_options = "bp0=$pattern0+0,action0=skip,bp1=$pattern1+0,action1=skip,bp2=$pattern2+0,action2=skip,count=0"

    strings:
        $pattern0 = { FF 75 08 E8 ?? ?? ?? ?? 59 }  // Check 1: Call to ___crtCorExitProcess with offset
        $pattern1 = { 59 FF 15 ?? ?? ?? ?? FF 75 08 }  // Check 2: Call to ExitProcess with address
        $pattern2 = { 55 8B EC FF 75 08 }  // Check 3: Stack frame setup for evasion logic

    condition:
        any of them
}