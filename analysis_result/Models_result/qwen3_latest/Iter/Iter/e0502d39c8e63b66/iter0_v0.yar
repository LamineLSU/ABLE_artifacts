rule Bypass_Sample
{
    meta:
        description = "Evasion bypass rule"
        cape_options = "bp0=$pattern0+0,action0=skip,bp1=$pattern1+0,action1=skip,bp2=$pattern2+0,action2=skip,count=0"

    strings:
        $pattern0 = { 56 FF 15 ?? ?? ?? ?? } // Push ESI + Call ExitProcess
        $pattern1 = { B9 00 00 42 00 FF 15 ?? ?? ?? ?? } // Mov ECX + Call GetModuleHandleA
        $pattern2 = { 83 65 E4 00 FF 15 ?? ?? ?? ?? } // And dword + Call GetStartupInfoA

    condition:
        any of them
}