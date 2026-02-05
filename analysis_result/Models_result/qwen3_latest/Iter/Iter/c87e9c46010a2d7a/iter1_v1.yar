rule Bypass_Sample_Evolved
{
    meta:
        description = "Evasion bypass rule - evolved"
        cape_options = "bp0=$pattern0+0,action0=skip,bp1=$pattern1+0,action1=skip,bp2=$pattern2+0,action2=skip,count=0"

    strings:
        $pattern0 = { 85 C0 0F 84 ?? ?? ?? ?? }  // TEST EAX, EAX + JE
        $pattern1 = { FF 15 ?? ?? ?? ?? }         // CALL to ExitProcess
        $pattern2 = { 50 E8 ?? ?? ?? ?? }         // PUSH + CALL (function call)

    condition:
        any of them
}