rule Bypass_Sample
{
    meta:
        description = "Evasion bypass rule"
        cape_options = "bp0=$pattern0+0,action0=skip,bp1=$pattern1+0,action1=skip,bp2=$pattern2+0,action2=skip,count=0"

    strings:
        $pattern0 = { 50 FF 15 ?? ?? ?? ?? }  // Push + Call TerminateProcess
        $pattern1 = { FF 75 08 FF 15 ?? ?? ?? ?? }  // Push [ebp+08h] + Call GetCurrentProcess
        $pattern2 = { E8 ?? ?? ?? ?? 83 F8 01 74 20 }  // Call + CMP EAX + JE

    condition:
        any of them
}