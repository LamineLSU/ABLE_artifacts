rule Bypass_Sample
{
    meta:
        description = "Evasion bypass rule"
        cape_options = "bp0=$pattern0+0,action0=skip,bp1=$pattern1+0,action1=skip,bp2=$pattern2+0,action2=skip,count=0"

    strings:
        $pattern0 = { FF 75 08 FF 15 ?? ?? ?? ?? }  // Push [ebp+08h] + Call ExitProcess (displacement wildcards)
        $pattern1 = { 59 E8 ?? ?? ?? ?? }            // Pop ecx + Call ___crtCorExitProcess (displacement wildcards)
        $pattern2 = { 8B EC FF 75 08 E8 ?? ?? ?? ?? }  // Mov ebp, esp + Push [ebp+08h] + Call ___crtCorExitProcess (displacement wildcards)

    condition:
        any of them
}